"""SOURCE wiring contracts; no imports of the core/helper, native IO or GUI.

These two leaves read only fixed first-party SOURCE files. They do not qualify
Tauri, TLS, native process settlement or an installed runtime.
"""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
COMMANDS = (
    "github_connection_status", "github_connection_connect_token",
    "github_connection_refresh", "github_connection_disconnect",
)


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


def section(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


class GitHubNativeWiringTests(unittest.TestCase):
    def test_closed_commands_match_handler_build_and_local_capability(self):
        shell = source("desktop/src-tauri/src/shell.rs")
        handlers = section(shell, ".invoke_handler(tauri::generate_handler![", "])")
        build = source("desktop/src-tauri/build.rs")
        capability = json.loads(source("desktop/src-tauri/capabilities/main.json"))
        self.assertTrue(capability["local"])
        self.assertNotIn("remote", capability)
        self.assertEqual(capability["windows"], ["main"])
        for command in COMMANDS:
            self.assertEqual(handlers.count(command), 1)
            self.assertEqual(build.count(f'"{command}"'), 1)
            self.assertEqual(capability["permissions"].count("allow-" + command.replace("_", "-")), 1)
            body = section(shell, f"async fn {command}(", "\n}")
            self.assertIn("fixture_command!(state, Forbidden", body)
            self.assertIn("github_connection_body(&webview, &request)?", body)
        entry = section(shell, "async fn github_connection_connect_token(", "\n}")
        self.assertNotIn(".await", entry)
        relay = section(shell, "fn start_relay(", "\nasync fn settle_relay(")
        self.assertIn("document.github_connection_status()", relay)
        self.assertIn("github_connection_wire::EVENT", relay)
        self.assertEqual(relay.count("Duration::from_millis(100)"), 1)

    def test_real_document_retirement_and_exit_do_not_change_vault_lock_semantics(self):
        document = source("desktop/src-tauri/src/asset_session.rs")
        session = source("desktop/src-tauri/src/github_connection_session.rs")
        bridge = source("desktop/src-tauri/src/bridge.rs")
        self.assertIn("github: ConnectionState", section(document, "struct DocumentState {", "\n}"))
        connect = section(document, "pub(crate) fn github_connection_connect_token(", "\n    }")
        self.assertLess(connect.index("self.github_gate(&state)"), connect.index("decode_command_value"))
        self.assertLess(connect.index("github_registration"), connect.index("state.github.connect("))
        self.assertNotIn(".await", connect)
        lookup = section(bridge, "pub(crate) fn github_registration(", "\n    }")
        self.assertLess(lookup.index("self.projects.lock()"), lookup.index("self.project_generation.load("))
        self.assertIn("projects.contains_key(id)", lookup)
        for forbidden in ("project.root", "project.path", "native_project", "std::fs", "clear_poison"):
            self.assertNotIn(forbidden, lookup)
        for name in ("fn loss_locked(", "fn gui_response(", "pub(crate) fn choose_project("):
            body = section(document, name, "\n    }")
            self.assertIn("state.github.retire(", body)
        choose = section(document, "pub(crate) fn choose_project(", "\n    }")
        self.assertLess(choose.index("state.github.retire("), choose.index("self.install("))
        self.assertIn("state.github.exhaust()", section(document, "fn exhaust(", "\n    }"))
        self.assertNotIn("github", section(document, "fn assets_can_exit_locked(", "\n}"))
        for name in ("async fn shutdown_assets(", "pub(crate) fn can_exit(", "fn retained_material_can_exit("):
            self.assertIn("state.github.material_settled()", section(document, name, "\n    }"))
        self.assertIn("const GITHUB_CONNECTION_NATIVE_QUALIFIED: bool = false;", session)
        self.assertNotIn("tokio::spawn", session)
        self.assertNotIn("Mutex<", session)
        self.assertNotIn("Serialize", section(session, "struct PrivateSession {", "\n}"))


if __name__ == "__main__":
    unittest.main()
