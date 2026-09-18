"""Inert resolver policy checks: supplied strings, never the namespace entry.

The one Bash child evaluates only the two reviewed pure function definitions.
It has no executable search path and performs no file, native or network work.
Native ancestry/alias/mount behavior remains a separate hosted obligation.
"""
from pathlib import Path
import re
import shlex
import subprocess
import unittest


NAMESPACE = Path(__file__).resolve().parents[2] / "desktop/src-tauri/tests/fixtures/github_tls_namespace.sh"
BEGIN = "# BEGIN PURE RESOLVER OWNERSHIP POLICY\n"
END = "# END PURE RESOLVER OWNERSHIP POLICY\n"


class ResolverOwnershipPolicyTests(unittest.TestCase):
    def test_actual_account_parser_and_exact_owner_routes(self):
        source = NAMESPACE.read_text(encoding="utf-8")
        self.assertEqual((source.count(BEGIN), source.count(END)), (1, 1))
        policy = source.split(BEGIN, 1)[1].split(END, 1)[0]
        self.assertEqual(re.findall(r"^([a-z_]+)\(\) \{$", policy, re.MULTILINE),
                         ["resolver_service_uid", "resolver_exact_owner"])
        for forbidden in ("$(", "`", "/usr/bin/", "/usr/sbin/", "source ", "exec ", "eval "):
            self.assertNotIn(forbidden, policy)
        account = "systemd-resolve:x:101:102:Resolver:/:/usr/sbin/nologin\n"
        rows = [
            ("named-service", "101", ("resolver_service_uid", "root:x:0:0::/:/bin/bash\n" + account, "1001")),
            ("bounded-uid", "4294967294", ("resolver_service_uid", account.replace(":101:", ":4294967294:"), "1001")),
            ("missing-service", None, ("resolver_service_uid", "root:x:0:0::/:/bin/bash\n", "1001")),
            ("runner-account", None, ("resolver_service_uid", account, "101")),
            ("zero-account", None, ("resolver_service_uid", account.replace(":101:", ":0:"), "1001")),
            ("leading-zero-account", None, ("resolver_service_uid", account.replace(":101:", ":0101:"), "1001")),
            ("overflow-account", None, ("resolver_service_uid", account.replace(":101:", ":4294967295:"), "1001")),
            ("long-account", None, ("resolver_service_uid", account.replace(":101:", ":10000000000:"), "1001")),
            ("overflow-group", None, ("resolver_service_uid", account.replace(":102:", ":4294967295:"), "1001")),
            ("negative-group", None, ("resolver_service_uid", account.replace(":102:", ":-1:"), "1001")),
            ("duplicate-account", None, ("resolver_service_uid", account + account, "1001")),
            ("malformed-duplicate", None, ("resolver_service_uid", account + "systemd-resolve:bad\n", "1001")),
            ("extra-field", None, ("resolver_service_uid", account.rstrip("\n") + ":\n", "1001")),
            ("missing-field", None, ("resolver_service_uid", "systemd-resolve:x:101:102:Resolver:/\n", "1001")),
            ("unterminated-account", None, ("resolver_service_uid", account.rstrip("\n"), "1001")),
            ("direct-root", "0", ("resolver_exact_owner", "/etc/resolv.conf", "0", "101", "1001")),
            ("direct-service-refused", None, ("resolver_exact_owner", "/etc/resolv.conf", "101", "101", "1001")),
            ("runtime-root", "0", ("resolver_exact_owner", "/run/systemd/resolve/stub-resolv.conf", "0", "0", "1001")),
            ("stub-service", "101", ("resolver_exact_owner", "/run/systemd/resolve/stub-resolv.conf", "101", "101", "1001")),
            ("full-service", "101", ("resolver_exact_owner", "/run/systemd/resolve/resolv.conf", "101", "101", "1001")),
            ("other-owner", None, ("resolver_exact_owner", "/run/systemd/resolve/resolv.conf", "102", "101", "1001")),
            ("runner-owner", None, ("resolver_exact_owner", "/run/systemd/resolve/resolv.conf", "1001", "1001", "1001")),
            ("unknown-path", None, ("resolver_exact_owner", "/tmp/resolv.conf", "0", "101", "1001")),
            ("noncanonical-path", None, ("resolver_exact_owner", "/run/systemd/resolve/../resolve/resolv.conf", "101", "101", "1001")),
            ("leading-zero-owner", None, ("resolver_exact_owner", "/run/systemd/resolve/resolv.conf", "0101", "101", "1001")),
            ("overflow-owner", None, ("resolver_exact_owner", "/run/systemd/resolve/resolv.conf", "4294967295", "101", "1001")),
            ("missing-service-authority", None, ("resolver_exact_owner", "/run/systemd/resolve/resolv.conf", "101", "0", "1001")),
        ]
        # No namespace script import/source, external command, runtime file or
        # socket. Each supplied row invokes one of the two functions above.
        commands = ["set -euo pipefail", policy, "passed=0"]
        for label, expected, arguments in rows:
            invocation = " ".join(shlex.quote(value) for value in arguments)
            if expected is None:
                commands.append(f"if result=$({invocation}); then printf '%s\\n' {shlex.quote(label)}; exit 1; fi")
            else:
                commands.append(f"result=$({invocation}); [[ $result == {shlex.quote(expected)} ]] || exit 1")
            commands.append("(( passed += 1 ))")
        commands.append("printf 'POLICY_CASES=%s\\n' \"$passed\"")
        completed = subprocess.run(
            ["/usr/bin/bash", "--noprofile", "--norc", "-c", "\n".join(commands)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd="/", env={"PATH": "/inert/no-tools", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            timeout=5, check=False,
        )
        self.assertEqual(completed.returncode, 0, "Inert resolver ownership policy refused a contract case")
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(completed.stdout, f"POLICY_CASES={len(rows)}\n".encode("ascii"))

    def test_role_is_wired_to_unchanged_file_and_mount_guards(self):
        source = NAMESPACE.read_text(encoding="utf-8")
        ordinary = source.split("ordinary() {\n", 1)[1].split("\n}\n", 1)[0]
        for invariant in ("canonical \"$pathname\"", "! -L $pathname", "16#$mode & 07022",
                          "links == 1", "uid == owner", "size > 0 && size <= maximum"):
            self.assertIn(invariant, ordinary)
        before_mount = source.split("/usr/bin/mount --no-mtab", 1)[0]
        for guard in (
            'ordinary /etc/passwd 0 65536',
            "read -r -d '' -n 65537 passwd_rows < /etc/passwd",
            '[[ $(stamp /etc/passwd) == "$passwd_stamp" ]] || refuse changed',
            'service_uid=$(resolver_service_uid "$passwd_rows" "$original_uid") || refuse identity',
            'for pathname in /run /run/systemd; do protected_host_directory "$pathname" 0; done',
            'protected_host_directory /run/systemd/resolve "$service_uid"',
            'alias_links == 1 && alias_uid == 0',
            '$alias_target == "$resolver_target" || $alias_target == "../${resolver_target#/}"',
            'resolver_owner=$(resolver_exact_owner "$resolver_target" "$observed_uid" "$service_uid" "$original_uid")',
            'ordinary "$resolver_target" "$resolver_owner" 65536',
            '$(stamp /etc/resolv.conf) == "$resolver_alias_stamp"',
            '$(stamp "$resolver_target") == "$resolver_target_stamp"',
            '$(stamp "${host_directories[index]}") == "${host_directory_stamps[index]}"',
        ):
            self.assertIn(guard, before_mount)
        self.assertIn('for pathname in /etc/hosts /etc/nsswitch.conf; do', before_mount)
        self.assertIn('ordinary "$pathname" 0 65536', before_mount)
        self.assertIn('exact_config "$resolver_target" "$resolver"', source)
        self.assertIn('remount,bind,ro,nosuid,nodev,noexec', source)
        self.assertNotIn("chown", source)
        self.assertNotIn("getent", source.replace("NSS/getent/id lookup", "lookup"))


if __name__ == "__main__":
    unittest.main()
