"""Pure source contracts: never import or execute hosted DATA provisioning."""

import ast
import hashlib
from pathlib import Path
import re
import unittest


SOURCE = Path(__file__).resolve().parents[2]
WORKFLOW = SOURCE / ".github/workflows/desktop-ubuntu-publication.yml"
DRIVER = SOURCE / "desktop/tools/ci_ubuntu_publication.py"
PROVISIONER = "desktop/tools/prepare_hosted_ubuntu_data.py"


class HostedWorkflowSource(unittest.TestCase):
    def test_fixed_jdk_preparation_is_conditional_paired_and_retains_original_failure_data(self):
        workflow = WORKFLOW.read_text()
        sections = re.split(r"^      - name: ", workflow, flags=re.MULTILINE)[1:]
        heading = "Prepare the fixed JDK17 pair only on this disposable shell runner"
        selected = [section for section in sections if section.splitlines()[0] == heading]
        self.assertEqual(len(selected), 1); step = selected[0]
        self.assertIn("        if: github.ref == 'refs/heads/verify/desktop-installed-shell'\n", step)
        self.assertIn("        timeout-minutes: 8\n", step)
        self.assertIn('[[ "$RUNNER_ENVIRONMENT" == github-hosted && "$GITHUB_REF" == refs/heads/verify/desktop-installed-shell ]]', step)
        self.assertIn('root="$RUNNER_TEMP/mrk-desktop-tools-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', step)
        self.assertIn('mkdir -m 700 -- "$root"', step)
        self.assertIn("          umask 077\n", step)
        self.assertLess(step.index("trap finish_tools_inputs EXIT"), step.index("query_packages before"))
        self.assertIn('pair=$(/usr/bin/python3.12 -I -S -B desktop/tools/ci_ubuntu_publication.py installed-shell-tools-before)', step)
        install = step.split('case "$pair" in\n', 1)[1].split('          esac\n', 1)[0]
        self.assertEqual(install.count("/usr/bin/apt-get"), 1)
        self.assertIn("            absent)\n", install)
        self.assertIn("            present) ;;\n            *) exit 1 ;;\n", install)
        self.assertIn("--no-install-recommends --no-remove", install)
        self.assertIn('install openjdk-17-jdk-headless > "$root/install.stdout" 2> "$root/install.stderr"', install)
        for name in ("java", "javac"):
            self.assertIn('sudo /usr/bin/update-alternatives --set ' + name + ' /usr/lib/jvm/java-17-openjdk-amd64/bin/' + name
                          + ' > "$root/' + name + '.stdout" 2> "$root/' + name + '.stderr"', step)
        finish = step.split("finish_tools_inputs() {\n", 1)[1].split("          }\n", 1)[0]
        self.assertLess(finish.index("original=$?"), finish.index("set +e"))
        self.assertIn("trap - EXIT", finish)
        self.assertLess(finish.index("query_packages after"), finish.index("installed-shell-tools-after"))
        self.assertIn('MRK_SHELL_TOOLS_PREPARATION_EXIT="$original" /usr/bin/python3.12 -I -S -B', finish)
        self.assertIn('snapshot=$?\n            if [[ "$original" != 0 ]]; then exit "$original"; fi\n            exit "$snapshot"', finish)
        for forbidden in ("apt-get update", "apt-get upgrade", "dist-upgrade", "--reinstall", "continue-on-error", "rm -", "pkill", "systemd-run", "java -version"):
            self.assertNotIn(forbidden, step)
        self.assertIn('git python3.12 openjdk-17-jdk-headless openjdk-17-jre-headless > "$root/$1-packages.tsv"', step)
        upload = next(section for section in sections if section.startswith("Retain original Tools prerequisite DATA including failures\n"))
        self.assertIn("        if: always() && steps.tools_inputs.outputs.root != ''\n", upload)
        self.assertIn("          path: ${{ steps.tools_inputs.outputs.root }}\n", upload)
        self.assertIn("          if-no-files-found: error\n", upload)
        self.assertLess(workflow.index("Prepare shared Ubuntu shell inputs"), workflow.index(heading))
        self.assertLess(workflow.index(heading), workflow.index("Establish only the reviewed forward glibc tuple set"))
        self.assertLess(workflow.index(heading), workflow.index("Prepare a fresh bounded compiler owner"))
        lifecycle = (SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_bytes()
        self.assertEqual(re.findall(r"MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256: '([0-9a-f]{64})'", workflow),
                         [hashlib.sha256(lifecycle).hexdigest()] * 2)

    def test_workflow_fits_its_actual_original_source_record_bound(self):
        module = ast.parse(DRIVER.read_text())
        for name, kib in (("verify_installed_shell_compile", 128), ("verify", 64)):
            with self.subTest(consumer=name):
                original = next(node for node in module.body
                                if isinstance(node, ast.FunctionDef) and node.name == name)
                calls = [node for node in ast.walk(original)
                         if isinstance(node, ast.Call)
                         and ast.unparse(node.func) == "D.file_record"
                         and len(node.args) == 2
                         and ast.unparse(node.args[0]) == "source / WORKFLOW"]
                self.assertEqual(len(calls), 1)
                self.assertEqual(ast.unparse(calls[0].args[1]), f"{kib} << 10")
                # Check each actual consumer, not a larger test-only cap.
                self.assertLessEqual(len(WORKFLOW.read_bytes()), kib << 10)

    def test_same_job_compiler_and_native_share_the_fixed_source_bound_data_script(self):
        workflow = WORKFLOW.read_text()
        heading = "      - name: Prepare only fixed disposable Ubuntu DATA modes\n"
        parts = workflow.split(heading)
        self.assertEqual(len(parts), 2)
        expected = (
            "        timeout-minutes: 1\n"
            "        shell: bash\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "
            "TZ=UTC HOME=/nonexistent /usr/bin/python3.12 -I -S -B "
            + PROVISIONER + " </dev/null\n"
        )
        self.assertEqual(parts[1].split("      - name:", 1)[0], expected)
        job = workflow.split("\njobs:\n", 1)[1]
        self.assertEqual(re.findall(r"^  ([a-z][a-z0-9_-]*):$", job, re.MULTILINE), ["compile"])
        self.assertNotIn("needs: compile", job)
        self.assertNotIn("needs.compile", job)
        self.assertLess(job.index("Prepare shared Ubuntu shell inputs"), job.index(heading))
        self.assertLess(job.index("Establish only the reviewed forward glibc tuple set"), job.index(heading))
        self.assertLess(job.index(heading), job.index("Observe only the hosted Python body"))
        self.assertLess(job.index("Observe only the hosted Python body"), job.index("Prepare a fresh bounded compiler owner"))
        sections = re.split(r"^      - name: ", job, flags=re.MULTILINE)[1:]

        def step(name):
            found = [section for section in sections if section.splitlines()[0] == name]
            self.assertEqual(len(found), 1, name)
            return found[0]

        compiler = step("Compile the normal shell and separate observer once without executing either")
        upload = step("Retain original compiler evidence and shell outputs")
        route = step("Require the fixed disposable native route")
        native_owner = step("Prepare a fresh bounded native owner")
        download = step("Download this run's exact original compiled shell outputs")
        consumer = step("Observe only the fixed installed shell route with original finality")
        sequence = (compiler, upload, route, native_owner, download, consumer)
        self.assertEqual([sections.index(section) for section in sequence],
                         sorted(sections.index(section) for section in sequence))
        self.assertIn("        id: compile\n", compiler)
        self.assertIn("        id: upload\n", upload)
        self.assertIn("        id: prepare_native\n", native_owner)
        gate = ("        if: github.ref == 'refs/heads/verify/desktop-installed-shell'"
                " && steps.compile.outcome == 'success' && steps.upload.outcome == 'success'\n")
        for section in (route, native_owner, download, consumer):
            self.assertIn(gate, section)
        bindings = (
            "MRK_INSTALLED_SHELL_ARTIFACT_ID: ${{ steps.upload.outputs.artifact-id }}",
            "MRK_INSTALLED_SHELL_ROSTER_SHA256: ${{ steps.compile.outputs.shell_roster_sha256 }}",
            "MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT: ${{ steps.compile.outputs.shell_producer_attempt }}",
        )
        for section in (route, consumer):
            for binding in bindings:
                self.assertIn(binding, section)
        self.assertIn('[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ && "$MRK_PUSH_EVENT_AFTER" == "$GITHUB_SHA" ]]', route)
        self.assertIn("re.fullmatch(r'[1-9][0-9]{0,19}', value)", route)
        self.assertIn("if int(values[1]) > int(values[2]) or not re.fullmatch(r'[0-9a-f]{64}'", route)
        self.assertIn("          run-id: ${{ github.run_id }}\n", download)
        self.assertIn("          artifact-ids: ${{ steps.upload.outputs.artifact-id }}\n", download)
        self.assertIn("          path: ${{ steps.prepare_native.outputs.root }}/work/admitted-shell\n", download)
        for field in ("root", "preparation_sha256", "deadline"):
            self.assertIn("${{ steps.prepare_native.outputs." + field + " }}", consumer)
        checkout = step("Check out exact reviewed source without credentials")
        self.assertIn("          ref: ${{ github.sha }}\n", checkout)
        self.assertIn("          persist-credentials: false\n", checkout)
        # Parse only: executing this privileged workflow-only script is forbidden
        # in these local checks. Its original globals must remain module globals.
        ast.parse((SOURCE / PROVISIONER).read_text())
        driver = ast.parse(DRIVER.read_text())
        manifest = next(node for node in driver.body
                        if isinstance(node, ast.FunctionDef) and node.name == "shell_source_manifest")
        assignments = [node for node in manifest.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "paths"
                               for target in node.targets)]
        self.assertEqual(len(assignments), 1)
        paths = ast.literal_eval(assignments[0].value)
        self.assertEqual(paths.count(PROVISIONER), 1)


class JvmNamespaceWorkflowSource(unittest.TestCase):
    def _program(self):
        """Extract SOURCE only. This literal is never imported, compiled or run."""
        workflow = WORKFLOW.read_text()
        marker, end = "<<'MRK_JVM_NAMESPACE'\n", "          MRK_JVM_NAMESPACE\n"
        self.assertEqual(workflow.count(marker), 1); self.assertEqual(workflow.count(end), 1)
        before, rest = workflow.split(marker, 1); body, after = rest.split(end, 1)
        self.assertTrue(all(not line or line.startswith("          ") for line in body.splitlines()))
        return workflow, before, "\n".join(line[10:] for line in body.splitlines()) + "\n", after

    def test_namespace_prephase_retains_original_status_and_gates_strict_before_and_apt(self):
        workflow, _, _, after = self._program()
        step = workflow.split("      - name: Prepare the fixed JDK17 pair only on this disposable shell runner\n", 1)[1].split("      - name:", 1)[0]
        sequence = ("query_packages before", "installed-shell-tools-namespace-before", "exec /usr/bin/sudo -n",
                    "namespace_status=$?", "printf '%s\\n' \"$namespace_status\" > \"$root/namespace.exit\"",
                    '[[ "$namespace_status" == 0 ]]', "installed-shell-tools-namespace-check",
                    "installed-shell-tools-before", 'case "$pair" in', "/usr/bin/apt-get", "/usr/bin/update-alternatives --set java",
                    "/usr/bin/update-alternatives --set javac")
        positions = [step.index(token) for token in sequence]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(step.count("query_packages before"), 1)
        self.assertEqual(step.count("installed-shell-tools-namespace-before"), 1)
        self.assertEqual(step.count("installed-shell-tools-namespace-check"), 1)
        self.assertIn('          ) > "$root/namespace.stdout" 2> "$root/namespace.stderr"\n'
                      '          namespace_status=$?\n          set -e\n'
                      '          printf \'%s\\n\' "$namespace_status" > "$root/namespace.exit"\n'
                      '          [[ "$namespace_status" == 0 ]]\n', after)
        prefix = step.split("exec /usr/bin/sudo -n", 1)[0]
        self.assertIn("installed-shell-tools-namespace-before\n          set +e\n          (\n            set -e\n", prefix)
        self.assertIn("          trap finish_tools_inputs EXIT\n          query_packages before\n", prefix)
        self.assertIn('if [[ "$original" != 0 ]]; then exit "$original"; fi', step)
        self.assertIn('exit "$snapshot"', step)
        for forbidden in ("continue-on-error", "|| true", "namespace_status=0", "trap restore", "--reinstall"):
            self.assertNotIn(forbidden, step)

    def test_literal_constructor_has_only_stdlib_and_the_closed_host_source_envelope(self):
        _, before, program, _ = self._program()
        tree = ast.parse(program)
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual(len(imports), 1); self.assertIsInstance(imports[0], ast.Import)
        self.assertEqual([alias.name for alias in imports[0].names],
                         ["hashlib", "json", "os", "re", "select", "signal", "stat", "subprocess", "sys", "time"])
        self.assertTrue(all(alias.asname is None for alias in imports[0].names))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self.assertNotIn(ast.unparse(node.func),
                                 {"exec", "eval", "compile", "__import__", "importlib.import_module", "os.system", "os.execv", "subprocess.run"})
        invocation = before.rsplit("exec /usr/bin/sudo -n /usr/bin/env -i ", 1)[1]
        self.assertIn("/usr/bin/timeout --signal=TERM --kill-after=2s 30s /usr/bin/python3.12 -I -S -B - ", invocation)
        environment = invocation.split("/usr/bin/timeout", 1)[0]
        keys = re.findall(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=", environment)
        expected_keys = {"PATH", "LANG", "LC_ALL", "TZ", "HOME", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT",
                         "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_JOB",
                         "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_WORKFLOW_REF",
                         "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "MRK_PUSH_EVENT_AFTER", "MRK_INSTALLED_SHELL_CASE",
                         "MRK_UBUNTU_PUBLICATION_VERIFY", "GITHUB_WORKSPACE", "RUNNER_TEMP"}
        self.assertEqual(set(keys), expected_keys); self.assertEqual(len(keys), len(expected_keys))
        for key in expected_keys - {"PATH", "LANG", "LC_ALL", "TZ", "HOME"}:
            self.assertIn(key + '="$' + key + '"', environment)
        self.assertIn("PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC HOME=/nonexistent", environment)
        self.assertNotIn("desktop/tools/", invocation)
        expected = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "expected" for target in node.targets))
        self.assertEqual(ast.literal_eval(expected.value),
                         {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
                          "ImageOS": "ubuntu24", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/verify/desktop-installed-shell",
                          "GITHUB_JOB": "compile", "GITHUB_REPOSITORY": "Apdelrahman1911/mobile-release-kit",
                          "MRK_INSTALLED_SHELL_CASE": "compile", "MRK_UBUNTU_PUBLICATION_VERIFY": "1"})
        for token in ('sys.argv == ["-"]', "sys.flags.isolated", "sys.flags.no_site", "sys.dont_write_bytecode",
                      'sys.platform == "linux"', "sys.version_info[:2] == (3, 12)", 'os.uname().machine == "x86_64"',
                      'os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0', 'os.getcwd() == "/"',
                      'env.get("GITHUB_WORKFLOW_SHA") == env.get("MRK_PUSH_EVENT_AFTER") == sha',
                      'env.get("GITHUB_WORKFLOW_REF") == expected["GITHUB_REPOSITORY"]',
                      're.fullmatch(r"[1-9][0-9]{0,19}", value)', 're.fullmatch(r"[0-9a-f]{40}", sha)',
                      're.fullmatch(r"[0-9]{8}\\.[0-9]{1,3}\\.[0-9]{1,3}", env.get("ImageVersion", ""))',
                      'all(item not in ("", ".", "..") for item in result)', 'same(report["sourceFiles"], original["sourceFiles"])'):
            self.assertIn(token, program)
        for forbidden in ("importlib", "exec_module", "runpy", "sys.path", "apt-get", "update-alternatives", "JAVA_HOME"):
            self.assertNotIn(forbidden, program)

    def test_one_fixed_package_query_has_bounded_original_wait_eofs_closes_and_failure_latch(self):
        _, before, program, _ = self._program()
        tree = ast.parse(program)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        popen = [node for node in calls if ast.unparse(node.func) == "subprocess.Popen"]
        self.assertEqual(len(popen), 1); call = popen[0]
        self.assertEqual(ast.literal_eval(call.args[0]),
                         ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Status}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n",
                          "openjdk-17-jdk-headless", "openjdk-17-jre-headless"])
        keywords = {item.arg: item.value for item in call.keywords}
        self.assertEqual(set(keywords), {"stdin", "stdout", "stderr", "cwd", "env", "close_fds"})
        for key, expected in (("stdin", "subprocess.DEVNULL"), ("stdout", "subprocess.PIPE"), ("stderr", "subprocess.PIPE")):
            self.assertEqual(ast.unparse(keywords[key]), expected)
        self.assertEqual(ast.literal_eval(keywords["cwd"]), "/"); self.assertIs(ast.literal_eval(keywords["close_fds"]), True)
        self.assertEqual(ast.literal_eval(keywords["env"]), {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "HOME": "/nonexistent"})
        waits = [node for node in calls if ast.unparse(node.func) == "child.wait"]
        self.assertEqual(len(waits), 2)
        self.assertEqual(sum(isinstance(item.value, ast.Constant) and item.arg == "timeout" and item.value.value == 2
                             for node in waits for item in node.keywords), 1)
        self.assertEqual(sum(ast.unparse(node.func) == "child.kill" for node in calls), 1)
        for forbidden in ("os.kill", "os.killpg", "signal.raise_signal", "subprocess.call", "subprocess.check_output"):
            self.assertFalse(any(ast.unparse(node.func) == forbidden for node in calls))
        query = program.split("def absent_pair_query():", 1)[1].split("\ntry:\n", 1)[0]
        for token in ('public_program("dpkg-query")', "end = min(deadline, time.monotonic() + 10)",
                      "os.set_blocking(fd, False)", "select.select(list(pending), [], [], left)",
                      "os.read(fd, 4097 - len(buffers[name]))", "need(len(buffers[name]) <= 4096)",
                      'q[name + "Eof"] = True', 'q["exitCode"] = child.wait(timeout=max(0.001, end - time.monotonic()))',
                      'q["originalReturned"] = True', 'failed = True', 'child.kill(); q["stopSent"] = True',
                      'q["exitCode"] = child.wait(timeout=2)', "stream.close()", 'q["streamsClosed"] = closed',
                      'need(not failed and q["originalReturned"] and q["streamsClosed"] and not q["stopSent"]',
                      'q["stdoutEof"] and q["stderrEof"] and q["exitCode"] == 1',
                      'bytes(buffers["stdout"]) == b"" and bytes(buffers["stderr"]) == MISSING'):
            self.assertIn(token, query)
        self.assertLess(query.index("failed = True"), query.index("child.kill()"))
        self.assertLess(query.index('q["exitCode"] = child.wait(timeout=2)'), query.index("stream.close()"))
        self.assertEqual(program.count("absent_pair_query()"), 2)  # Definition and one reached fixed call.
        self.assertIn("ulimit -v 262144; ulimit -t 15; ulimit -n 64; ulimit -c 0; ulimit -f 16", before)
        self.assertEqual(program.count("deadline = time.monotonic() + 20"), 1)
        self.assertIn("check_originals()\n    need(all(same(alias(path), nodes[path]) for path in aliases))", program)

    def test_effects_are_one_exclusive_dirfd_rename_then_a_distinct_new_inode_only(self):
        _, _, program, _ = self._program(); tree = ast.parse(program)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        effects = {name: [node for node in calls if ast.unparse(node.func) == "os." + name] for name in ("mkdir", "rename", "fchmod")}
        self.assertEqual({name: len(nodes) for name, nodes in effects.items()}, {"mkdir": 2, "rename": 1, "fchmod": 1})
        rename = effects["rename"][0]
        self.assertEqual([ast.literal_eval(arg) for arg in rename.args], ["jvm", "jvm"])
        self.assertEqual({item.arg: ast.unparse(item.value) for item in rename.keywords},
                         {"src_dir_fd": "lib_fd", "dst_dir_fd": "preserved_parent"})
        mkdirs = sorted(effects["mkdir"], key=lambda node: node.lineno)
        self.assertEqual([ast.unparse(arg) for arg in mkdirs[0].args], ["preservation_name", "448"])
        self.assertEqual(ast.literal_eval(mkdirs[1].args[0]), "jvm"); self.assertEqual(ast.literal_eval(mkdirs[1].args[1]), 0o755)
        for node in mkdirs:
            self.assertEqual({item.arg: ast.unparse(item.value) for item in node.keywords}, {"dir_fd": "lib_fd"})
        chmod = effects["fchmod"][0]
        self.assertEqual(ast.unparse(chmod.args[0]), "fresh_fd"); self.assertEqual(ast.literal_eval(chmod.args[1]), 0o755)
        self.assertEqual(chmod.keywords, [])
        guard = [node for node in ast.walk(tree) if isinstance(node, ast.If)
                 and any(call is rename for call in ast.walk(node))]
        self.assertEqual(len(guard), 1)
        self.assertEqual(ast.unparse(guard[0].test), "report['disposition'] == 'preserve-create'")
        self.assertTrue(all(any(child is call for child in ast.walk(guard[0])) for group in effects.values() for call in group))
        forbidden = {"os.chmod", "os.chown", "os.fchown", "os.replace", "os.link", "os.symlink", "os.unlink", "os.remove", "os.rmdir",
                     "os.listdir", "os.scandir", "os.walk", "shutil.copy", "shutil.copytree", "shutil.move", "shutil.rmtree"}
        self.assertFalse(any(ast.unparse(node.func) in forbidden for node in calls))
        order = ('os.mkdir(preservation_name, 0o700, dir_fd=lib_fd)', 'report["actions"]["preservationCreated"] = True',
                 'preserved_parent = opened(os.open(preservation_name', 'absent(preserved_parent, "jvm")',
                 'os.rename("jvm", "jvm", src_dir_fd=lib_fd, dst_dir_fd=preserved_parent)',
                 'report["actions"]["renameReturned"] = True', 'report["preserved"] = identity(os.stat("jvm"',
                 'os.mkdir("jvm", 0o755, dir_fd=lib_fd)', 'report["actions"]["freshCreated"] = True',
                 'fresh_fd = opened(os.open("jvm"', 'len({tuple(old[:2]), tuple(parent_id[:2]), tuple(fresh[:2])}) == 3',
                 'os.fchmod(fresh_fd, 0o755)')
        positions = [program.index(token) for token in order]; self.assertEqual(positions, sorted(positions))
        for token in ('need(old[2] == stat.S_IFDIR | 0o777)', 'old[3:5] == [0, 0]',
                      'parent_id[2:5] == [stat.S_IFDIR | 0o700, 0, 0]',
                      'fresh[2:5] == [stat.S_IFDIR | 0o755, 0, 0]',
                      'same(report["preserved"][:5], old[:5])', 'same(identity(os.fstat(old_fd))[:5], old[:5])',
                      'same(identity(os.stat("jvm", dir_fd=lib_fd, follow_symlinks=False))[:5], fresh[:5])',
                      'same(identity(os.stat(preservation_name, dir_fd=lib_fd, follow_symlinks=False))[:5], parent_id[:5])'):
            self.assertIn(token, program)
        for forbidden_text in ("exist_ok", "FileExistsError", "except OSError", "copytree", "mount(", "umount", "restore", "retry"):
            self.assertNotIn(forbidden_text, program.replace("never retry an uncertain return", ""))

    def test_protected_and_absent_originals_are_noops_without_descendant_repair(self):
        _, _, program, _ = self._program()
        before_effect = program.split('if report["disposition"] == "preserve-create":', 1)[0]
        self.assertIn('if absent(lib_fd, "jvm"):\n        need(nodes["/usr/lib/jvm"] == {"kind": "absent"})', before_effect)
        self.assertIn('report["disposition"] = "absent"\n        old_fd = None', before_effect)
        self.assertIn('protected = stat.S_ISDIR(old[2]) and old[2] & 0o022 == 0 and old[2] & 0o005 == 0o005', before_effect)
        self.assertIn('report["disposition"] = "protected" if protected else "preserve-create"', before_effect)
        self.assertIn('if not protected:\n            need(old[2] == stat.S_IFDIR | 0o777)', before_effect)
        self.assertIn('need(all(nodes[path] == {"kind": "parent-unavailable"} for path in node_names if path.startswith("/usr/lib/jvm/")))', before_effect)
        self.assertLess(before_effect.index("if not protected:"), before_effect.index("        absent_pair_query()"))
        self.assertEqual(before_effect.count("        absent_pair_query()"), 1)
        # Canonical absence/protection never silently becomes a newly chmodded original.
        for token in ("os.mkdir(", "os.rename(", "os.fchmod("):
            self.assertNotIn(token, before_effect)
        self.assertIn('elif old_fd is None:\n        need(absent(lib_fd, "jvm"))', program)
        self.assertIn('same(identity(os.fstat(old_fd)), report["original"])', program)
        self.assertIn('same(identity(os.stat("jvm", dir_fd=lib_fd, follow_symlinks=False)), report["original"])', program)

    def test_partial_effects_original_closes_and_output_failure_cannot_become_success(self):
        _, _, program, _ = self._program(); tree = ast.parse(program)
        report = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "report" for target in node.targets))
        original = ast.literal_eval(report.value)
        self.assertEqual(original["actions"], {"preservationCreated": False, "renameReturned": False, "freshCreated": False})
        self.assertIs(original["completed"], False); self.assertIs(original["originalFdsClosed"], False); self.assertIs(original["qualified"], False)
        for key in ("preservation", "preserved", "fresh", "query"):
            self.assertIsNone(original[key])
        self.assertIn('except BaseException:\n    report["failure"] = report["stage"]\nfinally:', program)
        self.assertIn('while fds:\n        fd = fds.pop()\n        try:\n            os.close(fd)', program)
        self.assertIn('except BaseException:\n            close_ok = False', program)
        self.assertIn('report["failure"] = report["failure"] or "original-fd-close"', program)
        self.assertIn('if report["failure"] is None and time.monotonic() >= deadline:', program)
        self.assertIn('if report["failure"] is None:\n    report["completed"] = True; report["stage"] = "complete"', program)
        self.assertIn('need(len(output) <= 16384 and os.write(1, output) == len(output))', program)
        self.assertIn('except BaseException:\n    raise SystemExit(1)', program)
        self.assertIn('raise SystemExit(0 if report["completed"] else 1)', program)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual(sum(ast.unparse(node.func) == "os.close" for node in calls), 1)
        self.assertEqual(sum(ast.unparse(node.func) == "os.write" for node in calls), 1)
        self.assertEqual(program.count('report["completed"] = True'), 1)
        # Every write/rename/collision failure keeps the reached stage and fails;
        # no handler adopts, restores, deletes, retries, or issues an APT command.
        handlers = [node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)]
        for handler in handlers:
            for node in ast.walk(handler):
                if isinstance(node, ast.Call):
                    self.assertNotIn(ast.unparse(node.func),
                                     {"os.mkdir", "os.rename", "os.replace", "os.chmod", "os.fchmod", "os.unlink", "os.rmdir", "subprocess.Popen"})

    def test_namespace_reads_and_source_records_keep_the_original_fixed_bounds(self):
        _, _, program, _ = self._program(); tree = ast.parse(program)
        sources = next(node for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "SOURCES" for target in node.targets))
        self.assertEqual(ast.literal_eval(sources.value),
                         ((".github/workflows/desktop-ubuntu-publication.yml", 65536), ("desktop/tools/ci_ubuntu_publication.py", 1048576)))
        driver = ast.parse(DRIVER.read_text())
        values = {target.id: node.value for node in driver.body if isinstance(node, ast.Assign)
                  for target in node.targets if isinstance(target, ast.Name)}
        for name, expected in (
            ("SHELL_TOOLS_NAMESPACE_SOURCES", {".github/workflows/desktop-ubuntu-publication.yml": "64 << 10",
                                              "desktop/tools/ci_ubuntu_publication.py": "1 << 20"}),
            ("SHELL_TOOLS_NAMESPACE_FILES", {"namespace-before.json": "64 << 10", "namespace.stdout": "16 << 10",
                                            "namespace.stderr": "4096", "namespace.exit": "4"}),
        ):
            value = values[name]
            self.assertIsInstance(value, ast.Dict)
            self.assertEqual({ast.literal_eval(key): ast.unparse(item) for key, item in zip(value.keys, value.values)}, expected)
        self.assertLessEqual(len(WORKFLOW.read_bytes()), 64 << 10)
        self.assertLessEqual(len(DRIVER.read_bytes()), 1 << 20)
        for token in ('read_file(root_fd, "namespace-before.json", 65536)', "stat.S_ISREG(before.st_mode) and before.st_nlink == 1",
                      "before.st_size <= limit", "os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC",
                      "os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK", "not os.get_inheritable(fd)",
                      'read_file(directories["/usr/bin"][0], name, 16 << 20)',
                      "same(identity(os.fstat(fd)), original)", "same(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), original)"):
            self.assertIn(token, program)


if __name__ == "__main__":
    unittest.main()
