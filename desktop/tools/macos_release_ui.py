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
CONSOLE_OCR = Path(__file__).with_name("macos_release_ui_privacy.swift")
PAGE_HEADINGS = {
    "Overview": "Get your app ready.",
    "Build & release": "Build and release your app",
    "Store listing": "Write your Store listing",
    "Signing & accounts": "Signing and Store accounts",
    "Project settings": "Set up your project",
    "Build tools": "Check your build tools",
    "GitHub": "Connect GitHub",
    "Build files": "Inspect a build",
    "Recover work": "Check interrupted work safely",
    "Automation": "Let a command-line tool help",
}
NAVIGATION_SCENARIOS = {"nav-" + re.sub(r"[^a-z]+", "-", page.lower()).strip("-"): page for page in PAGE_HEADINGS}
EXPECTED_SCENARIOS = {
    "native-console-admission", "cold-runtime-and-cli-denial", "cancel-native-project-picker",
    "project-picker-and-saved-config", *NAVIGATION_SCENARIOS, "cli-grant-and-revoke",
    "version-cancel-save-quit-reopen", "git-local-diff-and-no-side-effects", "window-layouts",
}


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


def verify_observation(work, media):
    evidence = work / "evidence"
    status_path = work / "observer-status"
    status = status_path.read_text().strip() if status_path.is_file() else "missing"
    result_path = evidence / "RESULT.json"
    result = json.loads(result_path.read_bytes()) if result_path.is_file() else {}
    scenarios = result.get("scenarios", {})
    statuses = {}
    for name in sorted(EXPECTED_SCENARIOS):
        state = scenarios.get(name, {}).get("status", "Not Tested")
        statuses[name] = state if state in {"Passed", "Failed", "Blocked", "Not Tested"} else "Invalid"
    summary = dict(observerExit=status if re.fullmatch(r"[0-9]{1,3}", status) else "unavailable",
                   scenarios=statuses, extraScenarioCount=len(scenarios.keys() - EXPECTED_SCENARIOS),
                   resultSha256=file_hash(result_path) if result_path.is_file() else None,
                   sourceCommit=result.get("sourceCommit"), harnessCommit=os.environ["GITHUB_SHA"])
    trace = evidence / "trace.jsonl"
    summary["traceSha256"] = file_hash(trace) if trace.is_file() else None
    payload = json.dumps(summary, sort_keys=True)
    (evidence / "SCENARIO-SUMMARY.json").write_text(payload + "\n")
    print(payload, flush=True)
    manifest_file = media / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_file.read_bytes())
    expected = {key: manifest[key] for key in ("sourceCommit", "sourceTree", "buildRun", "carrierRun")}
    expected.update(manifestSha256=file_hash(manifest_file),
                    packageSha256=manifest["packages"]["Install.pkg"]["sha256"],
                    removeSha256=manifest["packages"]["Remove.pkg"]["sha256"])
    need(all(result.get(key) == value for key, value in expected.items()), "observation-release-identity")
    need(status == "0", "observer-exit-status")
    need(scenarios.keys() == EXPECTED_SCENARIOS, "observation-scenario-roster")
    need(all(state == "Passed" for state in statuses.values()), "observation-scenario-failure")
    need(summary["traceSha256"] is not None, "observation-trace-absent")


def detach_install_media(mount, evidence):
    attempts = []
    try:
        for attempt in range(5):
            result = call("/usr/bin/hdiutil", "detach", str(mount), timeout=35, check=False)
            attempts.append(dict(returnCode=result.returncode, error=result.stderr.decode(errors="replace")[-500:]))
            if result.returncode != 16 or attempt == 4:
                return result.returncode
            # Installer can retain the read-only image briefly after its
            # success reply. Retry the detach, never Installer or a forced eject.
            time.sleep(2)
    except (OSError, subprocess.TimeoutExpired) as error:
        attempts.append(dict(error=type(error).__name__))
        return None
    finally:
        (evidence / "detach-install-media.json").write_text(json.dumps(attempts, indent=2) + "\n")


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
        state = json.loads(call("/usr/bin/sudo", "-n", "/bin/cat", str(PRODUCT / "installation-v2.json")).stdout)
        release = state["current"]["release"]
        need((release["sourceCommit"], release["packageVersion"], release["packageSha256"]) ==
             (manifest["sourceCommit"], manifest["version"], expected["sha256"]), "native-installed-identity")
        call("/usr/bin/codesign", "--verify", "--strict", str(APP))
        call("/usr/bin/codesign", "--verify", "--strict", str(PRODUCT / "Mobile Release Kit.app"))
        installed = dict(sourceCommit=release["sourceCommit"], packageSha256=expected["sha256"],
                         packageVersion=release["packageVersion"], nativeSignaturesVerified=True)
        (work / "evidence/INSTALLED.json").write_text(json.dumps(installed, indent=2) + "\n")
    finally:
        detached = detach_install_media(mount, work / "evidence")
    need(detached == 0, "installer-mounted-media-still-busy")
    shutil.copytree(FIXTURE, work / "MRK Verification Android")
    project = work / "MRK Verification Android"
    call("/usr/bin/git", "-C", str(project), "init", "-b", "main")
    call("/usr/bin/git", "-C", str(project), "add", "--all")
    call("/usr/bin/git", "-C", str(project), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-m", "Original synthetic project")


class UI:
    def __init__(self, client, evidence, screen):
        self.client = client
        self.evidence = evidence
        self.screen = screen
        self.count = 0
        self.project_name = None

    def command(self, name, **params):
        self.count += 1
        event = dict(sequence=self.count, timeNs=time.time_ns(), command=name, passed=False)
        if "selector" in params:
            event["selector"] = params["selector"]
        if name in ("element.click", "pointer.click", "pointer.scroll"):
            event["target"] = {key: params[key] for key in ("id", "x", "y", "dy") if key in params}
        try:
            result = self.client.command(name, params)
            event.update(passed=result["ok"], error=(result.get("error") or {}).get("code"))
        except Exception as error:
            event.update(error=type(error).__name__, httpStatus=getattr(error, "status", None))
            payload = getattr(error, "payload", None)
            if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
                event["errorCode"] = payload["error"].get("code")
            raise
        finally:
            with (self.evidence / "trace.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event) + "\n")
        need(result["ok"], f"{name}-{event['error']}")
        return result["result"]

    def node(self, name, *, category=None, contains=False, enabled=False, actionable=False, region=None):
        selector = {"text_contains": name, "visible": True}
        if category:
            selector["role"] = category
        if enabled:
            selector["enabled"] = True
        if region is None:
            found = self.command("element.wait", selector=selector, state="present", timeout_ms=10000)
            nodes = found["nodes"]
        else:
            found = self.command("tree.snapshot", limit=300)
            parents = [row for row in found["nodes"] if row["name"] == region and row["visible"]]
            need(len(parents) == 1, f"missing-or-ambiguous-region-{region}")
            prefix = parents[0]["id"] + "."
            nodes = [row for row in found["nodes"] if row["id"].startswith(prefix) and row["visible"]
                     and (not enabled or row["enabled"]) and (category is None or row["role"] == category)]
        if not contains:
            nodes = [node for node in nodes if name in (node.get("name"), node.get("text"))]
        if actionable and not category:
            nodes = [node for node in nodes if node["role"] in ("button", "disclosuretriangle")]
        need(len(nodes) == 1, f"missing-or-ambiguous-element-{name}")
        return found["snapshot_id"], nodes[0]

    def reveal(self, name, **selectors):
        # The action retains one snapshot. Read the window first so the
        # subsequent element observation is the one eligible for a click.
        pid = self.payload_pid()
        root = self.command("tree.snapshot", limit=1)["nodes"]
        snapshot, node = self.node(name, **selectors)
        need(len(root) == 1 and root[0]["role"] in ("window", "sheet") and root[0]["bounds"] and
             root[0]["id"] == f"mac:{pid}:0" and node["id"].startswith(root[0]["id"] + "."),
             "original-focused-app-window-or-sheet")
        window = root[0]["bounds"]
        top = max(0, window["y"] + (35 if root[0]["role"] == "window" else 3))
        bottom = min(self.screen["height"] - 65, window["y"] + window["height"] - 8)
        left = max(0, window["x"] + 3)
        right = min(self.screen["width"], window["x"] + window["width"]) - 3
        for _ in range(16):
            box = node["bounds"]
            x, y = box["x"] + box["width"] // 2, box["y"] + box["height"] // 2
            need(left <= x <= right, f"target-outside-window-width-{name}")
            if top <= y <= bottom:
                return snapshot, node
            # Keep the pointer in the target's own column. The sidebar and
            # document can move independently. Never click through the Dock.
            distance = y - (top + bottom) // 2
            dy = min(15, max(2, abs(distance) // 70)) * (1 if distance > 0 else -1)
            self.command("pointer.scroll", x=x, y=(top + bottom) // 2, dy=dy)
            snapshot, node = self.node(name, **selectors)
        raise AssertionError(f"target-not-reachable-in-app-viewport-{name}")

    def click(self, name, *, category=None, contains=False, region=None):
        for attempt in range(2):
            snapshot, node = self.reveal(name, category=category, contains=contains, region=region,
                                         enabled=True, actionable=True)
            try:
                self.command("element.click", snapshot_id=snapshot, id=node["id"])
                return
            except Exception as error:
                # The pinned action rejects a stale snapshot before sending
                # any pointer event. Re-observe once, with the same checks.
                payload = getattr(error, "payload", None)
                if (attempt or getattr(error, "status", None) != 409 or not isinstance(payload, dict) or
                    (payload.get("error") or {}).get("code") != "stale_snapshot"):
                    raise

    def edit(self, name, text):
        self.click(name, category="textfield", contains=True)
        self.keys("command", "a")
        self.command("text.insert", text=text)

    def keys(self, *keys):
        self.command("keyboard.press", keys=keys)

    def image(self, name):
        frame = self.client.fetch("/v1/screenshot")
        need(frame.startswith(b"\x89PNG\r\n\x1a\n"), "ui-screenshot-png")
        path = self.evidence / f"{name}.png"
        path.write_bytes(frame)
        return path

    def snapshot(self, name):
        tree = self.command("tree.snapshot", limit=160)
        (self.evidence / f"{name}-tree.json").write_text(json.dumps(tree, indent=2) + "\n")

    def local_network_decision(self, capabilities):
        def records(path):
            result = call("/usr/bin/swift", str(CONSOLE_OCR), str(path), timeout=45)
            return json.loads(result.stdout)

        def prompt(rows):
            return any("allow python to find devices" in row["text"].translate(
                str.maketrans("", "", "\"“”")).lower() for row in rows)

        evidence = dict(beforeApp=prompt(records(self.evidence / "before-app-launch.png")),
                        beforeDriver=prompt(records(self.evidence / "before-ui-driver.png")))
        rows = records(self.image("first-window"))
        evidence["afterDriver"] = prompt(rows)
        target = self.evidence / "local-network-decision.json"
        target.write_text(json.dumps(evidence, indent=2) + "\n")
        need(not evidence["beforeApp"], "unexpected-privacy-prompt-before-app")
        if not evidence["afterDriver"]:
            need(not evidence["beforeDriver"], "privacy-prompt-disappeared-without-a-decision")
            return

        def label(text):
            return [row for row in rows if row["text"].lower().replace("’", "'") == text]

        deny, allow = label("don't allow"), label("allow")
        need(len(deny) == len(allow) == 1, "exact-local-network-choice-labels")
        question = [row for row in rows if "find devices" in row["text"].lower()]
        need(len(question) == 1 and 0 < deny[0]["y"] - question[0]["y"] < 0.25 and
             abs(deny[0]["y"] - allow[0]["y"]) < 0.02 and 0 < allow[0]["x"] - deny[0]["x"] < 0.25,
             "exact-local-network-choice-geometry")
        screen = capabilities["screen"]
        self.command("pointer.click", x=round(deny[0]["x"] * screen["width"]),
                     y=round(deny[0]["y"] * screen["height"]))
        time.sleep(1)
        evidence["denied"] = not prompt(records(self.image("after-local-network-denial")))
        target.write_text(json.dumps(evidence, indent=2) + "\n")
        need(evidence["denied"], "local-network-prompt-remained-after-denial")

    def page(self, title):
        self.click(title, category="button", region="Workspace navigation")
        heading = self.project_name if title == "Overview" and self.project_name else PAGE_HEADINGS[title]
        self.reveal(heading, category="heading")

    def pick(self, project, *, cancel=False):
        self.click("Open another project folder" if self.project_name else "Choose project folder", category="button")
        self.node("Choose a mobile project folder", contains=True)
        if cancel:
            self.click("Cancel", category="button")
            self.node(PAGE_HEADINGS["Overview"], category="heading")
            return
        self.keys("command", "shift", "g")
        self.node("Go to Folder", contains=True)
        self.keys("command", "a")
        self.command("text.insert", text=str(project))
        self.keys("return")
        self.click("Open", category="button")
        self.node(project.name, category="heading")
        self.project_name = project.name

    def record_session(self, name, exercise):
        self.command("recording.start", duration_seconds=25)
        try:
            # Give the action's 2 fps recorder time for a frame before the
            # first serialized AX command holds its capture lock.
            time.sleep(1)
            exercise()
        except Exception:
            try:
                self.save_recording(name)
            except Exception:
                pass
            raise
        self.save_recording(name)

    def save_recording(self, name):
        self.command("recording.stop")
        frame = self.client.fetch("/v2/recording")
        need(frame.startswith((b"GIF87a", b"GIF89a")), "ui-recording-gif")
        (self.evidence / f"{name}.gif").write_bytes(frame)

    def payload_pid(self):
        active = call("/usr/bin/pgrep", "-f", PAYLOAD_PATTERN).stdout.splitlines()
        need(len(active) == 1, "exact-original-payload")
        return int(active[0])

    def reopened_payload(self, prior_pid):
        reply = call("/usr/bin/pgrep", "-f", PAYLOAD_PATTERN, check=False)
        need(reply.returncode in (0, 1), "reopened-payload-process-observation")
        if reply.returncode == 1:
            return None
        pids = reply.stdout.splitlines()
        need(len(pids) == 1, "ambiguous-reopened-payload")
        pid = int(pids[0])
        nodes = self.command("tree.snapshot", limit=1)["nodes"]
        return pid if pid != prior_pid and len(nodes) == 1 and nodes[0]["id"] == f"mac:{pid}:0" and \
            nodes[0]["role"] == "window" and nodes[0]["name"] == "Mobile Release Kit" else None

    def resize(self, width, height):
        pid = self.payload_pid()

        def window():
            nodes = self.command("tree.snapshot", limit=1)["nodes"]
            need(len(nodes) == 1 and nodes[0]["id"] == f"mac:{pid}:0" and nodes[0]["role"] == "window" and
                 nodes[0]["name"] == "Mobile Release Kit", "exact-focused-payload-window")
            rows = [row for row in self.command("windows.list")["windows"]
                    if row["process_id"] == pid and row["title"] == nodes[0]["name"] and row["bounds"] == nodes[0]["bounds"]]
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
                   buildRun=manifest["buildRun"], carrierRun=manifest["carrierRun"],
                   manifestSha256=file_hash(media / "RELEASE-MANIFEST.json"),
                   packageSha256=manifest["packages"]["Install.pkg"]["sha256"],
                   removeSha256=manifest["packages"]["Remove.pkg"]["sha256"], scenarios={})
    scenarios = results["scenarios"]
    (evidence / "RESULT.json").write_text(json.dumps(results, indent=2) + "\n")
    connection, client = open_session(work, action)
    capabilities = json.loads(client.fetch("/v2/capabilities"))
    ui = UI(client, evidence, capabilities["screen"])
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
            try:
                ui.snapshot(name + "-failure")
            except Exception:
                pass
        finally:
            save()
        return scenarios[name]["status"] == "Passed"

    def start_observation():
        results["commands"] = sorted(capabilities["commands"])
        if not {"element.wait", "element.click", "tree.snapshot"} <= set(capabilities["commands"]):
            raise Blocked("macOS Accessibility is unavailable to the action on this runner")
        ui.local_network_decision(capabilities)
        ui.snapshot("first-window")

    def startup():
        ui.page("Build tools")
        ui.click("Advanced · app connection details", contains=True)
        ui.node("Bundled runtime", category="heading")
        need(call(str(CLI), "status", "--json", check=False).returncode == 3, "initial-cli-denial")

    def cancel_picker():
        ui.page("Overview")
        ui.pick(project, cancel=True)
        need(all(file_hash(project / name) == digest for name, digest in original.items()),
             "cancelled-project-picker-changed-fixture")

    def select_project():
        ui.page("Overview")
        ui.pick(project)
        ui.click("Project details & saved observations", contains=True)
        ui.node(str(project), category="statictext")
        ui.node("org.mrk.fixture", contains=True)
        ui.click("Edit version & build number")
        ui.click("Open saved version editor", category="button")
        ui.node("Values: 1.0.0 · Build 1.", category="statictext", contains=True)
        need(all(file_hash(project / name) == digest for name, digest in original.items()), "project-originals")

    def permission_lifecycle():
        ui.page("Project settings")
        ui.click("Advanced · CLI / AI access", contains=True)
        ui.click("Check access", category="button")
        ui.click("Allow selected project for 1 hour", category="button")
        ui.node("1 project was allowed at last check", category="statictext", contains=True)
        need(call(str(CLI), "status", "--json", check=False).returncode == 0, "cli-native-grant")
        projects = json.loads(call(str(CLI), "projects", "--json").stdout)
        response = projects["response"]
        need(response["kind"] == "projects" and len(response["value"]) == 1
             and response["value"][0]["registeredInCurrentHost"] is True, "cli-project-readback")
        ui.click("Turn off access", category="button")
        ui.node("Off at last check", category="statictext", contains=True)
        need(call(str(CLI), "status", "--json", check=False).returncode == 4, "cli-native-revocation")

    def versions():
        ui.page("Overview")
        ui.node("Values: 1.0.0 · Build 1.", category="statictext", contains=True)
        ui.edit("Build number", "x")
        ui.node("Enter a marketing-version string", contains=True)
        _, refused = ui.node("Validate and review values", category="button")
        need(not refused["enabled"] and file_hash(project / VERSION_FILE) == original[VERSION_FILE],
             "invalid-build-input-was-admitted")
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
        prior_pid = ui.payload_pid()
        ui.keys("command", "q")
        ui.node("Quit and discard unsaved drafts?", category="statictext", contains=True)
        ui.click("Quit", category="button")
        until(lambda: call("/usr/bin/pgrep", "-f", PAYLOAD_PATTERN, check=False).returncode == 1,
              18, "original-payload-did-not-quit")
        call("/usr/bin/open", "-a", str(APP))
        end = time.monotonic() + 12
        reopened_pid = until(lambda: ui.reopened_payload(prior_pid), end - time.monotonic(),
                             "exact-reopened-payload-window")
        results["reopenedPayload"] = {"original": prior_pid, "reopened": reopened_pid}
        ui.click("Overview", category="button")
        empty = PAGE_HEADINGS["Overview"]
        def reopened_overview():
            snapshot = ui.command("tree.snapshot")
            matches = {value for node in snapshot["nodes"] if node["role"] == "heading" and node["visible"]
                       for value in (node.get("name"), node.get("text")) if value in (empty, project.name)}
            need(len(matches) <= 1, "ambiguous-reopened-overview")
            return matches.pop() if matches else None
        if until(reopened_overview, end - time.monotonic(), "reopened-overview-not-rendered") == empty:
            ui.project_name = None
            ui.pick(project)
        ui.click("Edit version & build number")
        ui.click("Open saved version editor", category="button")
        ui.node("Values: 1.0.1 · Build 2.", category="statictext", contains=True)
        need((project / VERSION_FILE).read_bytes() == expected
             and file_hash(project / CONFIG_FILE) == original[CONFIG_FILE], "reopened-saved-values")

    def git_observation():
        readme = project / "README.md"
        marker = b"\nSynthetic signed candidate UI verification.\n"
        readme.write_bytes(readme.read_bytes() + marker)
        def git(*args):
            return call("/usr/bin/git", "-C", str(project), *args).stdout
        before = git("status", "--porcelain=v1")
        head = git("rev-parse", "HEAD")
        need(b" M README.md\n" in before, "synthetic-worktree-change")
        ui.page("GitHub")
        ui.click("Connect", category="radiobutton", region="GitHub tasks")
        ui.click("Check local Git access", category="button")
        ui.node("Local Git reader available", category="heading")
        ui.click("Refresh changes", category="button")
        ui.click("Select README.md", category="checkbox")
        ui.click("Working changes", category="button")
        ui.node(marker.strip().decode(), contains=True)
        need(git("status", "--porcelain=v1") == before and git("rev-parse", "HEAD") == head
             and git("diff", "--cached", "--name-only") == b"", "git-read-affected-repository")

    def window_layouts():
        screen = json.loads(client.fetch("/v2/capabilities"))["screen"]
        width, height = min(screen["width"] - 32, 1180), min(screen["height"] - 75, 740)
        if width < 980 or height < 690:
            raise Blocked("The synthetic console is too small for two readable window sizes")
        results["windowBounds"] = []
        for width, height in ((width - 40, height - 20), (width, height)):
            results["windowBounds"].append(ui.resize(width, height))
            ui.page("Overview")
            ui.page("Project settings")
            ui.image(f"settings-{width}x{height}")

    try:
        if scenario("native-console-admission", lambda: ui.record_session("console-admission", start_observation)):
            scenario("cold-runtime-and-cli-denial", startup)
            scenario("cancel-native-project-picker", cancel_picker)
            selected = scenario("project-picker-and-saved-config", select_project)
            for label, page in NAVIGATION_SCENARIOS.items():
                scenario(label, lambda page=page: ui.page(page))
            if selected:
                scenario("cli-grant-and-revoke", permission_lifecycle)
                scenario("version-cancel-save-quit-reopen", versions)
                scenario("git-local-diff-and-no-side-effects", git_observation)
            else:
                scenarios["cli-grant-and-revoke"] = dict(status="Blocked", reason="Fixture project selection failed")
                scenarios["version-cancel-save-quit-reopen"] = dict(status="Blocked", reason="Fixture project selection failed")
                scenarios["git-local-diff-and-no-side-effects"] = dict(status="Blocked", reason="Fixture project selection failed")
            scenario("window-layouts", window_layouts)
        else:
            for name in ("project-picker-and-saved-config", "cli-grant-and-revoke", "workspace-navigation",
                         "version-cancel-save-quit-reopen", "window-layouts", "git-local-diff-and-no-side-effects"):
                scenarios[name] = dict(status="Blocked", reason="Original UI session or initialization did not pass")
    finally:
        save()
        (connection.parent / "stop").touch()
    return 0 if scenarios and all(row["status"] == "Passed" for row in scenarios.values()) else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("install", "observe", "require"))
    parser.add_argument("media", type=Path)
    parser.add_argument("work", type=Path)
    parser.add_argument("--action", type=Path)
    args = parser.parse_args()
    if args.mode == "install":
        install(args.media, args.work)
        return 0
    if args.mode == "require":
        verify_observation(args.work, args.media)
        return 0
    return observe(args.work, args.action, args.media)


if __name__ == "__main__":
    raise SystemExit(main())
