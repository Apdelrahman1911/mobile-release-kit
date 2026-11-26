"""Exercise the installed release through a pinned ui-test-actions loopback session."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import time


APP = Path("/Applications/Mobile Release Kit.app")
PRODUCT = Path("/Library/Application Support/MobileReleaseKit")
CLI = PRODUCT / "Mobile Release Kit.app/Contents/MacOS/mrk"
FIXTURE = Path("tests/fixtures/macos_android_journey")
VERSION_FILE = Path("public/version.properties")
CONFIG_FILE = Path("release/mobile-release.json")
PAYLOAD_PATTERN = r"[/]MobileReleaseKitPayload\.app/Contents/MacOS/mobile-release-kit-desktop( |$)"
PAGES = (
    "Overview", "Build & release", "Store listing", "Signing & accounts",
    "Project settings", "Build tools", "GitHub", "Build files", "Recover work", "Automation",
)


class Blocked(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise AssertionError(reason)


def call(*argv, timeout=90, check=True):
    return subprocess.run(argv, timeout=timeout, check=check, capture_output=True)


def until(operation, timeout, reason):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = operation()
        if value:
            return value
        time.sleep(0.5)
    raise AssertionError(reason)


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def install(media, work):
    manifest = json.loads((media / "RELEASE-MANIFEST.json").read_bytes())
    name = f"MobileReleaseKit-{manifest['version']}-macos-arm64-Install.dmg"
    image = media / name
    need(file_hash(image) == manifest["images"][name]["sha256"], "exact-install-disk-image")
    reply = call("/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-plist", str(image))
    mounts = [Path(row["mount-point"]) for row in plistlib.loads(reply.stdout)["system-entities"]
              if "mount-point" in row]
    need(len(mounts) == 1 and mounts[0].parent == Path("/Volumes"), "exact-install-volume")
    mount = mounts[0]
    try:
        package = mount / "Install.pkg"
        expected = manifest["packages"]["Install.pkg"]
        for file, digest in ((package, expected["sha256"]), (mount / "producer.json", expected["descriptorSha256"]),
                             (mount / "producer.sig", expected["signatureSha256"])):
            need(file_hash(file) == digest, "signed-install-contents")
        outcome = call("/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package), "-target", "/",
                       timeout=180, check=False)
        (work / "evidence/installer.log").write_bytes(outcome.stdout[-65536:] + outcome.stderr[-65536:])
        need(outcome.returncode == 0, "installer-original-return")
    finally:
        call("/usr/bin/hdiutil", "detach", str(mount))
    state = json.loads(call("/usr/bin/sudo", "-n", "/bin/cat", str(PRODUCT / "installation-v2.json")).stdout)
    release = state["current"]["release"]
    need((release["sourceCommit"], release["packageVersion"], release["packageSha256"]) ==
         (manifest["sourceCommit"], manifest["version"], manifest["packages"]["Install.pkg"]["sha256"]),
         "native-installed-identity")
    call("/usr/bin/codesign", "--verify", "--strict", str(APP))
    call("/usr/bin/codesign", "--verify", "--strict", str(PRODUCT / "Mobile Release Kit.app"))
    shutil.copytree(FIXTURE, work / "MRK Verification Android")
    project = work / "MRK Verification Android"
    call("/usr/bin/git", "-C", str(project), "init", "-b", "main")
    call("/usr/bin/git", "-C", str(project), "add", "--all")
    call("/usr/bin/git", "-C", str(project), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-m", "Original synthetic project")


class UI:
    def __init__(self, client, evidence):
        self.client = client
        self.evidence = evidence
        self.count = 0

    def command(self, name, **params):
        result = self.client.command(name, params)
        self.count += 1
        code = result.get("error", {}).get("code")
        with (self.evidence / "trace.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(sequence=self.count, timeNs=time.time_ns(), command=name,
                                         passed=result["ok"], error=code)) + "\n")
        need(result["ok"], f"{name}-{code}")
        return result["result"]

    def node(self, name, *, category=None, contains=False):
        selector = {"text_contains" if contains else "name": name, "visible": True}
        if category:
            selector["role"] = category
        found = self.command("element.wait", selector=selector, timeout_ms=16000)
        need(found["matched"] == 1, f"ambiguous-element-{name}")
        return found["snapshot_id"], found["nodes"][0]

    def click(self, name, *, category=None, contains=False):
        snapshot, node = self.node(name, category=category, contains=contains)
        need(node.get("enabled"), f"disabled-element-{name}")
        self.command("element.click", snapshot_id=snapshot, id=node["id"])

    def edit(self, name, text):
        self.click(name, category="textfield", contains=True)
        self.keys("command", "a")
        self.command("text.insert", text=text)

    def keys(self, *keys):
        self.command("keyboard.press", keys=keys)

    def image(self, name):
        frame = self.client.fetch("/v1/screenshot")
        need(frame.startswith(b"\x89PNG\r\n\x1a\n"), "ui-screenshot-png")
        (self.evidence / f"{name}.png").write_bytes(frame)

    def page(self, title):
        self.click(title, category="button")
        def page_content():
            return any(title in (node.get("name"), node.get("text")) and node.get("visible")
                       and node.get("role") in ("heading", "statictext")
                       for node in self.command("tree.snapshot")["nodes"])
        until(page_content, 12, f"visible-page-{title}")

    def pick(self, project, *, first=False):
        self.click("Choose project folder" if first else "Open another project folder", category="button")
        self.node("Choose a mobile project folder", contains=True)
        self.keys("command", "shift", "g")
        self.command("text.insert", text=str(project))
        self.keys("return")
        self.click("Open", category="button")

    def record_session(self, name, exercise):
        self.command("recording.start", duration_seconds=25)
        try:
            exercise()
        finally:
            self.command("recording.stop")
            frame = self.client.fetch("/v2/recording")
            need(frame.startswith((b"GIF87a", b"GIF89a")), "ui-recording-gif")
            (self.evidence / f"{name}.gif").write_bytes(frame)

    def resize(self, width, height):
        active = call("/usr/bin/pgrep", "-f", PAYLOAD_PATTERN).stdout.splitlines()
        need(len(active) == 1, "exact-original-payload")
        pid = int(active[0])

        def window():
            rows = [row for row in self.command("windows.list")["windows"] if row["process_id"] == pid]
            need(len(rows) == 1 and rows[0]["bounds"] is not None, "exact-original-window")
            return rows[0]

        original = window()
        self.command("windows.move_resize", id=original["id"], width=width, height=height, x=20, y=55)
        observed = window()["bounds"]
        need(abs(observed["width"] - width) <= 1 and abs(observed["height"] - height) <= 1,
             "observed-window-size")
        return observed


def open_session(work, action):
    def new_connection():
        previous = set(json.loads((work / "previous-sessions.json").read_bytes()))
        found = [path for path in Path(os.environ["RUNNER_TEMP"]).glob("ui-session-*/connection.json")
                 if str(path) not in previous]
        need(len(found) <= 1, "unique-ui-session")
        return found[0] if found else None

    path = until(new_connection, 260, "ui-action-never-ready")
    spec = importlib.util.spec_from_file_location("pinned_ui_client", action / "agent.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    connection = json.loads(path.read_bytes())
    need(connection["transport"] == "local" and connection["target"] == "macos", "loopback-only-session")
    need(re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", connection["url"]), "loopback-only-origin")
    return path, module.Client(connection, work / "token")


def observe(work, action, media):
    evidence = work / "evidence"
    manifest = json.loads((media / "RELEASE-MANIFEST.json").read_bytes())
    results = dict(sourceCommit=manifest["sourceCommit"], sourceTree=manifest["sourceTree"],
                   packageSha256=manifest["packages"]["Install.pkg"]["sha256"], scenarios={})
    scenarios = results["scenarios"]
    (evidence / "RESULT.json").write_text(json.dumps(results, indent=2) + "\n")
    connection, client = open_session(work, action)
    ui = UI(client, evidence)
    project = work / "MRK Verification Android"
    original = {path.relative_to(project): file_hash(path) for path in project.rglob("*")
                if path.is_file() and ".git" not in path.relative_to(project).parts}

    def save():
        tmp = evidence / "RESULT.next"
        tmp.write_text(json.dumps(results, indent=2) + "\n")
        tmp.replace(evidence / "RESULT.json")

    def scenario(name, exercise):
        try:
            exercise()
            ui.image(name)
            scenarios[name] = dict(status="Passed")
        except Blocked as error:
            scenarios[name] = dict(status="Blocked", reason=str(error))
        except Exception as error:
            scenarios[name] = dict(status="Failed", reason=f"{type(error).__name__}: {error}"[:180])
            try:
                ui.image(name + "-failure")
            except Exception:
                pass
        finally:
            save()
        return scenarios[name]["status"] == "Passed"

    def startup():
        ui.image("first-window")
        capabilities = json.loads(client.fetch("/v2/capabilities"))
        results["commands"] = sorted(capabilities["commands"])
        if not {"element.wait", "element.click", "tree.snapshot"} <= set(capabilities["commands"]):
            raise Blocked("macOS Accessibility is unavailable to the action on this runner")
        ui.page("Build tools")
        ui.click("Advanced · app connection details")
        ui.node("Bundled runtime", category="statictext", contains=True)
        need(call(str(CLI), "status", "--json", check=False).returncode == 3, "initial-cli-denial")

    def select_project():
        ui.page("Overview")
        ui.pick(project, first=True)
        ui.click("Edit version & build number")
        ui.click("Open saved version editor", category="button")
        ui.node("Values: 1.0.0 · Build 1.", category="statictext", contains=True)
        need(all(file_hash(project / name) == digest for name, digest in original.items()), "project-originals")

    def permission_lifecycle():
        ui.page("Project settings")
        ui.click("Advanced · CLI / AI access")
        ui.click("Check access", category="button")
        ui.click("Allow selected project for 1 hour", category="button")
        ui.node("1 project was allowed at last check", category="statictext", contains=True)
        need(call(str(CLI), "status", "--json", check=False).returncode == 0, "cli-native-grant")
        need(call(str(CLI), "projects", "--json", check=False).returncode == 0, "cli-project-readback")
        ui.click("Turn off access", category="button")
        ui.node("Off at last check", category="statictext", contains=True)
        need(call(str(CLI), "status", "--json", check=False).returncode == 4, "cli-native-revocation")

    def versions():
        ui.page("Overview")
        ui.node("Values: 1.0.0 · Build 1.", category="statictext", contains=True)
        ui.edit("Marketing version", "1.0.1")
        ui.edit("Build number", "2")
        ui.click("Validate and review values", category="button")
        ui.node("Edit only the two selected value spans", category="heading", contains=True)
        ui.click("Save version values…", category="button")
        ui.node("Save the new version?", category="heading", contains=True)
        ui.click("Keep reviewing", category="button")
        need(file_hash(project / VERSION_FILE) == original[VERSION_FILE], "cancelled-save-modified-version")
        ui.click("Save version values…", category="button")
        ui.click("I reviewed the change.", category="checkbox")
        ui.click("Save version values", category="button")
        ui.node("Submitted version values saved", category="statictext", contains=True)
        expected = b"VERSION_NAME=1.0.1\nBUILD_NUMBER=2\n"
        need((project / VERSION_FILE).read_bytes() == expected, "exact-saved-version")
        need(all(file_hash(project / name) == digest for name, digest in original.items() if name != VERSION_FILE),
             "save-touched-another-input")
        ui.keys("command", "q")
        ui.node("Quit and discard unsaved drafts?", category="statictext", contains=True)
        ui.click("Quit", category="button")
        until(lambda: call("/usr/bin/pgrep", "-f", PAYLOAD_PATTERN, check=False).returncode == 1,
              18, "original-payload-did-not-quit")
        call("/usr/bin/open", "-a", str(APP))
        ui.page("Overview")
        ui.pick(project, first=True)
        ui.click("Edit version & build number")
        ui.click("Open saved version editor", category="button")
        ui.node("Values: 1.0.1 · Build 2.", category="statictext", contains=True)
        need((project / VERSION_FILE).read_bytes() == expected
             and file_hash(project / CONFIG_FILE) == original[CONFIG_FILE], "reopened-saved-values")

    def window_layouts():
        screen = json.loads(client.fetch("/v2/capabilities"))["screen"]
        if screen["width"] < 1200 or screen["height"] < 800:
            raise Blocked("The synthetic console is too small for the two controlled sizes")
        results["windowBounds"] = []
        for width, height in ((1100, 700), (1180, 740)):
            results["windowBounds"].append(ui.resize(width, height))
            ui.page("Overview")
            ui.page("Project settings")
            ui.image(f"settings-{width}x{height}")

    try:
        if scenario("cold-runtime-and-cli-denial", lambda: ui.record_session("cold-runtime", startup)):
            selected = scenario("project-picker-and-saved-config", select_project)
            for page in PAGES:
                label = "nav-" + re.sub(r"[^a-z]+", "-", page.lower()).strip("-")
                scenario(label, lambda page=page: ui.page(page))
            scenario("window-layouts", window_layouts)
            if selected:
                scenario("cli-grant-and-revoke", permission_lifecycle)
                scenario("version-cancel-save-quit-reopen", versions)
            else:
                scenarios["cli-grant-and-revoke"] = dict(status="Blocked", reason="Fixture project selection failed")
                scenarios["version-cancel-save-quit-reopen"] = dict(status="Blocked", reason="Fixture project selection failed")
        else:
            for name in ("project-picker-and-saved-config", "cli-grant-and-revoke", "workspace-navigation",
                         "version-cancel-save-quit-reopen", "window-layouts"):
                scenarios[name] = dict(status="Blocked", reason="Original UI session or initialization did not pass")
    finally:
        save()
        (connection.parent / "stop").touch()
    return 0 if scenarios and all(row["status"] == "Passed" for row in scenarios.values()) else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("install", "observe"))
    parser.add_argument("media", type=Path)
    parser.add_argument("work", type=Path)
    parser.add_argument("--action", type=Path)
    args = parser.parse_args()
    if args.mode == "install":
        install(args.media, args.work)
        return 0
    return observe(args.work, args.action, args.media)


if __name__ == "__main__":
    raise SystemExit(main())
