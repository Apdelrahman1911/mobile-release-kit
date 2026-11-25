"""Actual workflow argv checks; local Bash is not macOS build evidence."""
from pathlib import Path
import json
import shlex
import subprocess
import unittest


class MacOSOptionalArraysTests(unittest.TestCase):
    def test_optional_arrays_preserve_empty_and_quoted_argv_under_nounset(self):
        path = Path(__file__).absolute().parents[2] / ".github/workflows/desktop-macos-installed.yml"
        with path.open("rb") as stream:
            body = stream.read(512 * 1024 + 1)
        self.assertLessEqual(len(body), 512 * 1024)
        root=path.parents[2]
        def yaml(p):
            return json.loads(subprocess.run(['ruby','-ryaml','-rjson','-e',
                'puts JSON.generate(YAML.safe_load(File.read(ARGV[0]),aliases:true))',str(p)],
                check=True,capture_output=True,timeout=10).stdout)
        workflow=yaml(path)
        actions={}
        def runs(step):
            if 'run' in step:return [step['run']]
            route=step.get('uses','')
            if not route.startswith('./.github/actions/'):return []
            action_path=root/route/'action.yml'
            self.assertTrue(action_path.resolve().is_relative_to(root/'.github/actions'))
            self.assertLessEqual(action_path.stat().st_size,512*1024)
            if route not in actions:actions[route]=yaml(action_path)
            action=actions[route]
            self.assertEqual(action['runs']['using'],'composite')
            result=[]
            for inner in action['runs']['steps']:
                for text in runs(inner):
                    for name,value in step.get('with',{}).items():
                        text=text.replace('${{ inputs.'+name+' }}',value)
                    result.append(text)
            return result
        # Keep the original exact counts on the original engineering recipe.
        # Inspect the actual expanded candidate recipes as well.
        original=workflow['jobs']['engineering-install']['steps']
        source='\n'.join(text for step in original for text in runs(step))
        forms = {name: '${' + name + '[@]+"${' + name + '[@]}"}' for name in
                 ("history_provider_arguments", "removal_arguments", "github_seal_arguments")}
        for name, count in (("history_provider_arguments", 1), ("removal_arguments", 3), ("github_seal_arguments", 1)):
            self.assertEqual(source.count(forms[name]), count)
            self.assertNotIn('"${' + name + '[@]}"', source.replace(forms[name], ""))
        # Display labels vary between the ordinary app and native observer.
        # Select the existing stable step ID, then still test its real argv.
        prefix = '"$MRK_PYTHON" -I -S -B desktop/tools/stage_macos_installed.py app --target "$MRK_MACOS_TARGET" '
        assemblies=[]
        for job in workflow['jobs'].values():
            steps=job.get('steps',[])
            for step in steps:
                texts=runs(step)
                text='\n'.join(texts)
                for name,form in forms.items():
                    self.assertNotIn('"${'+name+'[@]}"',text.replace(form,''))
                if step.get('id')=='app_assemble':assemblies.append(text)
        self.assertEqual(len(assemblies),3)
        for assembly in assemblies:
            self.assertIn("set -euo pipefail\n",assembly)
            calls=[line.strip() for line in assembly.splitlines() if line.strip().startswith(prefix)]
            self.assertEqual(len(calls),1)
            self.assertTrue(calls[0].endswith(" \\") )
            actual=calls[0][len(prefix):-2]
            self.assertEqual(actual,forms['removal_arguments']+' '+forms['github_seal_arguments'])
        script = ["set -euo pipefail", "emit_argv() { builtin printf '%s\\0' \"$@\"; }"]
        expected = []

        def array(name, values):
            script.append(name + "=(" + " ".join(shlex.quote(value) for value in values) + ")")

        def emit(command, values):
            script.append(command)
            expected.extend(values)

        # Only harmless builtins run: no source command, stager, or native tool.
        cases = ((), ("one",), ("two words", "literal*?[x]"), ("", " space ", "literal$(not-a-command)"))
        for name, form in forms.items():
            for values in cases:
                array(name, values)
                emit("emit_argv leading " + form + " trailing", ("leading", *values, "trailing"))
            script.append("unset -v " + name)
            emit("emit_argv leading " + form + " trailing", ("leading", "trailing"))
        script.extend(("MRK_MACOS_TARGET='inert target'", "MRK_PYTHON=emit_argv"))
        for removal, seal in (((), ()), (("--removal-abrupt-fixture",), ()),
                              ((), ("--github-seal", "capsule path *[x]", "")),
                              (("one", "two words"), ("", "literal?glob"))):
            array("removal_arguments", removal)
            array("github_seal_arguments", seal)
            emit(prefix.strip() + " " + actual + " --package-role ordinary-image",
                 ("-I", "-S", "-B", "desktop/tools/stage_macos_installed.py", "app", "--target", "inert target",
                  *removal, *seal, "--package-role", "ordinary-image"))
        script = "\n".join(script) + "\n"
        expected = b"".join(value.encode("utf-8") + b"\0" for value in expected)
        self.assertLessEqual(len(script.encode("utf-8")), 16384)
        self.assertLessEqual(len(expected), 8192)
        result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", script],
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main()
