"""Inert dpkg/apt DATA policy controls; no package tool, process or native call."""
import importlib.util
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("hosted_glibc_policy", SOURCE / "desktop/tools/hosted_glibc_policy.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def rows(version=S.OLD):
    result = {name + ":" + arch: dict(zip(S.FIELDS, (name, arch, version, "glibc", version, "install ok installed")))
              for name, arch in S.PACKAGES.items()}
    for name in ("libgcc-s1", "linux-libc-dev", "libcrypt-dev", "rpcsvc-proto", "unrelated-held"):
        result[name + ":amd64"] = dict(zip(S.FIELDS, (name, "amd64", "1.0", "not-glibc", "1.0",
                                           "hold ok installed" if name == "unrelated-held" else "install ok installed")))
    return result


def encode(values):
    return "".join("\t".join(values[key][field] for field in S.FIELDS) + "\n" for key in sorted(values)).encode("ascii")


def simulation(values):
    changes = [row for row in S.selected(values).values() if row["version"] == S.OLD]
    lines = [f"{len(changes)} upgraded, 0 newly installed, 0 to remove and 19 not upgraded."]
    for row in changes:
        origin = f"Ubuntu:24.04/noble-security [{row['architecture']}]"
        lines += [f"Inst {row['package']} [{S.OLD}] ({S.NEW} {origin})",
                  f"Conf {row['package']} ({S.NEW} {origin})"]
    return ("\n".join(lines) + "\n").encode("ascii")


class HostedGlibcPolicyContracts(unittest.TestCase):
    def test_exact_forward_upgrade_and_noop_keep_the_complete_nonselected_snapshot(self):
        for version in (S.OLD, S.NEW):
            with self.subTest(version=version):
                original = rows(version)
                before = S.snapshot(encode(original))
                self.assertEqual(before, original)
                self.assertEqual(S.arguments(before), [key + "=" + S.NEW for key in sorted(S.selected(before))])
                self.assertEqual(S.simulation(simulation(before), before), sorted(S.selected(before)) if version == S.OLD else [])
                S.after(before, rows(S.NEW))
        # Apt may annotate temporary unmet dependencies within the explicitly
        # selected upgrade set. This does not authorize an extra package action.
        raw = simulation(rows()).replace(b")\n", b") [libc6:amd64 libc6-dev:amd64 ]\n", 1)
        S.simulation(raw, rows())

    def test_unknown_newer_older_held_partial_foreign_and_missing_inputs_refuse(self):
        changes = (
            lambda value: value["libc6:amd64"].update(version="2.39-0ubuntu8.10", sourceVersion="2.39-0ubuntu8.10"),
            lambda value: value["libc6:amd64"].update(version="2.39-0ubuntu8.7", sourceVersion="2.39-0ubuntu8.7"),
            lambda value: value["libc6:amd64"].update(sourceVersion=S.NEW),
            lambda value: value["libc6:amd64"].update(sourcePackage="different-source"),
            lambda value: value["libc6:amd64"].update(status="hold ok installed"),
            lambda value: value["libc6:amd64"].update(status="install ok unpacked"),
            lambda value: value["libc6:amd64"].update(architecture="i386"),
            lambda value: value.update({"nscd:amd64": {**value["libc6:amd64"], "package": "nscd"}}),
            lambda value: value.pop("libc-dev-bin:amd64"),
            lambda value: value.pop("linux-libc-dev:amd64"),
        )
        for index, change in enumerate(changes):
            value = rows(); change(value)
            with self.subTest(change=index), self.assertRaises(S.Refused):
                S.arguments(S.snapshot(encode(value)))
        for raw in (encode(rows()) * 2, encode(rows()).rstrip(b"\n"), b"not a package table\n"):
            with self.subTest(raw=raw[:40]), self.assertRaises(S.Refused):
                S.snapshot(raw)

    def test_simulation_cannot_add_remove_repair_downgrade_or_omit_original_actions(self):
        original = rows()
        raw = simulation(original)
        lines = raw.splitlines(keepends=True)
        changes = (
            raw + f"Inst unrelated-held [1.0] ({S.NEW} Ubuntu:24.04/noble-security [amd64])\n".encode(),
            raw + b"Remv unrelated-held [1.0]\n",
            raw.replace(S.NEW.encode(), b"2.39-0ubuntu8.10", 1),
            raw.replace(b"0 newly installed", b"1 newly installed", 1),
            raw.replace(b"0 to remove", b"1 to remove", 1),
            b"".join(lines[:-1]), raw + lines[-1],
            raw.replace(b")\n", b") [unrelated-held:amd64 ]\n", 1),
            raw.replace(b"Conf ", b"Unknown ", 1),
        )
        for value in changes:
            with self.subTest(raw=value[-100:]), self.assertRaises(S.Refused):
                S.simulation(value, original)

    def test_postcondition_rejects_any_unselected_metadata_or_selected_target_change(self):
        before = rows()
        for change in (
            lambda value: value.pop("unrelated-held:amd64"),
            lambda value: value.update({"new:amd64": {**value["unrelated-held:amd64"], "package": "new"}}),
            lambda value: value["unrelated-held:amd64"].update(version="2.0"),
            lambda value: value["unrelated-held:amd64"].update(status="install ok installed"),
            lambda value: value["libc6:amd64"].update(version=S.OLD),
            lambda value: value["libc6:amd64"].update(sourceVersion=S.OLD),
            lambda value: value["libc6:amd64"].update(status="install ok unpacked"),
        ):
            value = rows(S.NEW); change(value)
            with self.subTest(change=change), self.assertRaises(S.Refused):
                S.after(before, value)

    def test_only_fixed_same_source_disposable_setup_routes_are_admitted(self):
        repository = "Apdelrahman1911/mobile-release-kit"
        common = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                  "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": repository,
                  "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40, "MRK_PUSH_EVENT_AFTER": "a" * 40,
                  "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1"}
        for ref, job, case in S.ROUTES:
            env = {**common, "GITHUB_REF": ref, "GITHUB_JOB": job,
                   "GITHUB_WORKFLOW_REF": repository + "/.github/workflows/desktop-ubuntu-publication.yml@" + ref}
            if case is not None:
                env["MRK_INSTALLED_SHELL_CASE"] = case
            self.assertEqual(S.context(env)["GITHUB_JOB"], job)
            for change in ({"GITHUB_JOB": "native"}, {"GITHUB_REF": "refs/heads/main"},
                           {"MRK_INSTALLED_SHELL_CASE": "observe"}, {"GITHUB_WORKFLOW_SHA": "b" * 40},
                           {"RUNNER_ENVIRONMENT": "self-hosted"}, {"GITHUB_RUN_ATTEMPT": "0"}):
                with self.subTest(change=change), self.assertRaises(S.Refused):
                    S.context({**env, **change})

    def test_workflow_requires_simulation_returned_apt_and_postconditions_before_compilation(self):
        workflow = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        setup = workflow.split("      - name: Establish only the reviewed forward glibc tuple set", 1)[1].split(
            "      - name: Retain original glibc prerequisite DATA", 1)[0]
        self.assertIn("timeout-minutes: 8", setup)
        for fixed in ("set -euo pipefail", "mkdir -m 700", "--no-remove", "--only-upgrade", "allow-Downgrades=false",
                      "allow-Change-Held-Packages=false", "allow-Remove-Essential=false", "allow-Unauthenticated=false"):
            self.assertIn(fixed, setup)
        indices = [setup.index(value) for value in ("before.tsv", "hosted_glibc_policy.py plan", "--simulate install",
            "hosted_glibc_policy.py simulation", '"${options[@]}" -y install', "after.tsv", "hosted_glibc_policy.py after")]
        self.assertEqual(indices, sorted(indices))
        self.assertNotIn("--allow-downgrades", setup)
        self.assertNotIn("--fix-broken", setup)
        self.assertNotIn("|| true", setup)
        self.assertIn("if: always() && steps.glibc.outputs.root != ''", workflow)

    def test_python_data_observer_route_matches_the_actual_single_job_lane(self):
        # Only the pure context function is called, never the host-file observer.
        spec = importlib.util.spec_from_file_location("hosted_python_context", SOURCE / "desktop/tools/observe_hosted_python.py")
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        workflow = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        publisher = "\n  publisher-helpers:\n" in workflow
        repository = "Apdelrahman1911/mobile-release-kit"
        ref = "refs/heads/verify/desktop-ubuntu-publication" if publisher else "refs/heads/verify/desktop-installed-shell"
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
               "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": repository,
               "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40, "MRK_PUSH_EVENT_AFTER": "a" * 40,
               "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REF": ref,
               "GITHUB_JOB": "publisher-helpers" if publisher else "compile", "ImageOS": "ubuntu24",
               "ImageVersion": "20260920.314.1",
               "GITHUB_WORKFLOW_REF": repository + "/.github/workflows/desktop-ubuntu-publication.yml@" + ref}
        for case in (None,) if publisher else ("compile", "observe"):
            if case is not None:
                env["MRK_INSTALLED_SHELL_CASE"] = case
            self.assertEqual(observer.context(env)["GITHUB_JOB"], env["GITHUB_JOB"])
            for change in ({"GITHUB_JOB": "native"}, {"GITHUB_REF": "refs/heads/main"},
                           {"GITHUB_WORKFLOW_SHA": "b" * 40}, {"RUNNER_ENVIRONMENT": "self-hosted"}):
                with self.subTest(change=change), self.assertRaises(observer.Refused):
                    observer.context({**env, **change})


if __name__ == "__main__":
    unittest.main()
