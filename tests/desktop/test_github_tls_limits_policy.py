"""Exercise only fixed limit functions with an in-memory Bash ulimit stand-in.

No real limit setter, namespace entry, service, network or native fixture runs.
The ordinary bounded shell evaluates only the reviewed delimited functions.
"""
from pathlib import Path
import re
import shlex
import subprocess
import unittest


SOURCE = Path(__file__).resolve().parents[2]
NAMESPACE = SOURCE / "desktop/src-tauri/tests/fixtures/github_tls_namespace.sh"
BEGIN = "# BEGIN FIXED TLS RESOURCE LIMIT POLICY\n"
END = "# END FIXED TLS RESOURCE LIMIT POLICY\n"


class TLSResourceLimitPolicyTests(unittest.TestCase):
    def policy(self):
        source = NAMESPACE.read_text(encoding="utf-8")
        self.assertEqual((source.count(BEGIN), source.count(END)), (1, 1))
        policy = source.split(BEGIN, 1)[1].split(END, 1)[0]
        self.assertEqual(re.findall(r"^([a-z_]+)\(\) \{$", policy, re.MULTILINE),
                         ["tls_limit_value", "tls_limit_at_least", "tls_limit_pair", "fixed_tls_resource_limits"])
        commands = "\n".join(line for line in policy.splitlines() if not line.lstrip().startswith("#"))
        for forbidden in ("builtin ", "command ", "`", "/usr/bin/", "/usr/sbin/", "source ", "exec ", "eval "):
            self.assertNotIn(forbidden, commands)
        return policy

    def shell(self, commands, expected):
        # ulimit is replaced BEFORE definitions or calls. The zero-tool PATH,
        # fixed argv and timeout do not execute the privileged namespace entry.
        script = "set -euo pipefail\nulimit() { printf 'UNEXPECTED_LIMIT_CALL\\n'; exit 97; }\n"
        script += self.policy() + "\n" + commands
        completed = subprocess.run(
            ["/usr/bin/bash", "--noprofile", "--norc", "-c", script], cwd="/",
            env={"PATH": "/inert/no-tools", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5, check=False,
        )
        self.assertEqual(completed.returncode, 0, "Inert fixed resource-policy contract failed")
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(completed.stdout, expected)

    def test_canonical_limits_and_unsigned_lower_only_order(self):
        rows = [
            (True, "0", "0"), (True, "128", "128"), (True, "1024", "128"),
            (True, "unlimited", "unlimited"), (True, "unlimited", "1048576"),
            (True, "18446744073709551615", "9223372036854775808"),
            (False, "128", "1024"), (False, "0", "1"), (False, "1", "unlimited"),
        ]
        for bad in ("", " 1024", "1024 ", "01024", "-1", "+1", "1.0", "1\n2", "Unlimited",
                    "18446744073709551616", "999999999999999999999", "1+1", "1;false"):
            rows.extend(((False, bad, "0"), (False, "unlimited", bad)))
        commands = []
        for accepted, current, minimum in rows:
            invocation = "tls_limit_at_least " + shlex.quote(current) + " " + shlex.quote(minimum)
            commands.append((invocation + " || exit 92") if accepted else
                            ("if " + invocation + "; then exit 93; fi"))
        commands.append(f"printf 'ORDER_CASES={len(rows)}\\n'")
        self.shell("\n".join(commands), f"ORDER_CASES={len(rows)}\n".encode())

    def test_fixed_tuple_mutations_readbacks_and_failure_stop(self):
        # Only mock setters update 'calls'. Getter command substitutions use
        # these same parent values, so readback/fault selection cannot disappear
        # through a subshell-local counter. No real ulimit is reachable.
        mock = r'''
declare -A limits
calls=()
fault=none
fault_flag=-f
ulimit() {
    [[ ( $# == 2 || $# == 3 ) && ( $1 == -S || $1 == -H ) ]] || exit 94
    local side=$1 flag=$2 key="$1:$2"
    case "$flag" in -c|-f|-n|-v) ;; *) exit 94 ;; esac
    if [[ $# == 2 ]]; then
        if [[ $flag == "$fault_flag" ]]; then
            [[ $fault != get-soft || $side != -S ]] || return 1
            [[ $fault != get-hard || $side != -H ]] || return 1
            if [[ ${#calls[@]} -gt 0 && ${calls[-1]} == "-H:$flag:"* ]]; then
                [[ $fault != readback-error ]] || return 1
                if [[ $fault == readback-drift && $side == -S ]]; then printf 'unlimited\n'; return 0; fi
            fi
        fi
        printf '%s\n' "${limits[$key]}"
        return 0
    fi
    calls+=("$side:$flag:$3")
    if [[ $flag == "$fault_flag" ]]; then
        [[ $fault != set-soft || $side != -S ]] || return 1
        [[ $fault != set-hard || $side != -H ]] || return 1
    fi
    limits[$key]=$3
}
refuse() { printf 'refused:%s\n' "$1"; exit 71; }
run_case() (
    action=$1 initial=$2 fault=$3 fault_flag=$4 changed_side=$5 changed=$6
    calls=()
    for flag in -c -f -n -v; do
        target=0
        case "$flag" in -f) target=1024 ;; -n) target=128 ;; -v) target=1048576 ;; esac
        value=$initial
        [[ $initial != exact ]] || value=$target
        limits[-S:$flag]=$value; limits[-H:$flag]=$value
    done
    [[ $changed_side == none ]] || limits[$changed_side:$fault_flag]=$changed
    trap 'printf "calls:%s\n" "${calls[*]}"' EXIT
    fixed_tls_resource_limits "$action"
)
'''
        all_calls = [f"{side}:{flag}:{value}" for flag, value in
                     (("-c", 0), ("-f", 1024), ("-n", 128), ("-v", 1048576)) for side in ("-S", "-H")]
        rows = []
        for initial in ("unlimited", "exact", "18446744073709551615"):
            rows.append((("enforce", initial, "none", "-f", "none", ""), None, all_calls))
        rows.append((("verify", "exact", "none", "-f", "none", ""), None, []))
        for index, (flag, code, target) in enumerate((
                ("-c", "limit-core", 0), ("-f", "limit-file", 1024),
                ("-n", "limit-descriptors", 128), ("-v", "limit-address-space", 1048576))):
            prefix = all_calls[:2 * index]
            for fault, extra in (("get-soft", 0), ("get-hard", 0), ("set-soft", 1),
                                 ("set-hard", 2), ("readback-error", 2), ("readback-drift", 2)):
                rows.append((("enforce", "unlimited", fault, flag, "none", ""), code,
                             prefix + all_calls[2 * index:2 * index + extra]))
            for side in ("-S", "-H"):
                rows.append((("enforce", "unlimited", "none", flag, side, "010"), code, prefix))
                if target:
                    rows.append((("enforce", "exact", "none", flag, side, str(target - 1)), code, prefix))
                rows.append((("verify", "exact", "none", flag, side, str(target + 1)), code, []))
            rows.append((("enforce", "exact", "none", flag, "-S", "unlimited"), code, prefix))
        commands = [mock]
        for number, (args, code, calls) in enumerate(rows):
            command = "run_case " + " ".join(shlex.quote(value) for value in args)
            expected_status = 0 if code is None else 71
            expected = ("" if code is None else f"refused:{code}\n") + "calls:" + " ".join(calls)
            commands.extend((
                f"rc=0; result=$({command}) || rc=$?",
                f"[[ $rc == {expected_status} && $result == {shlex.quote(expected)} ]] || "
                f"{{ printf 'CASE_FAILED={number}\\n'; exit 95; }}",
            ))
        # No caller can turn this into a general launcher or choose new limits.
        for invocation in ("tls_limit_pair -n 129 enforce", "tls_limit_pair -f 1024 reset",
                           "tls_limit_pair -t 60 enforce", "tls_limit_pair -c 1 enforce"):
            commands.append(f"if {invocation}; then exit 96; fi")
        commands.append("if (set -o posix; fixed_tls_resource_limits enforce) >/dev/null; then exit 96; fi")
        commands.append(f"printf 'FIXED_CASES={len(rows)}\\n'")
        self.shell("\n".join(commands), f"FIXED_CASES={len(rows)}\n".encode())

    def test_namespace_enforces_before_setup_and_checks_before_exec(self):
        source = NAMESPACE.read_text(encoding="utf-8")
        self.assertEqual(source.count("\nfixed_tls_resource_limits enforce\n"), 1)
        self.assertEqual(source.count("\nfixed_tls_resource_limits verify\n"), 1)
        self.assertLess(source.index('&& $netns != "$parent_netns"'), source.index("\nfixed_tls_resource_limits enforce\n"))
        self.assertLess(source.index("\nfixed_tls_resource_limits enforce\n"), source.index("canonical()"))
        self.assertLess(source.index("\ncd -- \"$root\"\n"), source.index("\nfixed_tls_resource_limits verify\n"))
        self.assertLess(source.index("\nfixed_tls_resource_limits verify\n"), source.index("exec /usr/bin/setpriv"))
        self.assertIn("--clear-groups", source)
        self.assertIn("--inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs", source)
        rust = (SOURCE / "desktop/src-tauri/src/hosted_tests.rs").read_text(encoding="utf-8")
        start = rust.index("        fn nonzero_file_limit() -> bool {")
        ambient = rust[start:rust.index("\n        }", start)]
        self.assertIn("soft > 0 && soft <= hard && hard <= 1024 * 1024", ambient)


if __name__ == "__main__":
    unittest.main()
