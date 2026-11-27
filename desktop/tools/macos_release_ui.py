"""Exercise the installed release through a pinned ui-test-actions loopback session."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import stat
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
    "project-switch-and-cli-isolation", "version-cancel-save-quit-reopen", "git-local-diff-and-no-side-effects", "window-layouts",
}
SUITE_SCENARIOS = {
    "workspace": EXPECTED_SCENARIOS,
    "metadata": {"native-console-admission", "project-picker-and-saved-config", "metadata-negative-cancel-save-readback"},
    "projects": {"native-console-admission", "project-picker-and-saved-config", "project-switch-and-cli-isolation"},
    "cli-read": {"native-console-admission", "project-picker-and-saved-config", "installed-cli-read-data-and-refusals"},
    "git-index": {"native-console-admission", "project-picker-and-saved-config", "git-index-review-stage-unstage"},
    "vault-lifecycle": {"native-console-admission", "project-picker-and-saved-config", "vault-cancel-lock-reopen"},
    "vault-profile": {"native-console-admission", "project-picker-and-saved-config", "vault-profile-save-bind-unlock"},
    "reopen-projects": {"native-console-admission", "project-picker-and-saved-config", "version-cancel-save-quit-reopen",
                        "project-switch-and-cli-isolation"},
}
METADATA_TITLE = Path("public/store/android/en-US/title.txt")


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


def verify_observation(work, media, suite):
    evidence = work / "evidence"
    status_path = work / "observer-status"
    status = status_path.read_text().strip() if status_path.is_file() else "missing"
    result_path = evidence / "RESULT.json"
    result = json.loads(result_path.read_bytes()) if result_path.is_file() else {}
    scenarios = result.get("scenarios", {})
    expected_scenarios = SUITE_SCENARIOS[suite]
    statuses = {}
    for name in sorted(expected_scenarios):
        state = scenarios.get(name, {}).get("status", "Not Tested")
        statuses[name] = state if state in {"Passed", "Failed", "Blocked", "Not Tested"} else "Invalid"
    summary = dict(observerExit=status if re.fullmatch(r"[0-9]{1,3}", status) else "unavailable",
                   scenarios=statuses, extraScenarioCount=len(scenarios.keys() - expected_scenarios),
                   suite=suite,
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
    need(result.get("suite") == suite, "observation-suite-identity")
    need(status == "0", "observer-exit-status")
    need(scenarios.keys() == expected_scenarios, "observation-scenario-roster")
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


def install(media, work, suite):
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
        capability_bytes = call(str(CLI), "capabilities", "--json").stdout
        need(0 < len(capability_bytes) <= 65536, "bounded-compiled-cli-capabilities")
        capability = json.loads(capability_bytes)
        need(capability["scope"] == "compiled-interface" and capability["runtimeChecked"] is False
             and capability["supportsDirectMutationCommands"] is False, "static-cli-capability-contract")
        (work / "evidence/CLI-CAPABILITIES.json").write_bytes(capability_bytes)
    finally:
        detached = detach_install_media(mount, work / "evidence")
    need(detached == 0, "installer-mounted-media-still-busy")
    project = work / ("MRK Verification iOS" if suite == "vault-profile" else "MRK Verification Android")
    if suite == "vault-profile":
        fixture = json.loads(Path("desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-persistence-v1.json").read_bytes())
        for relative, encoded in fixture["files"].items():
            if relative.startswith("project/") or relative == "sources/synthetic.mobileprovision":
                target = (project / relative.removeprefix("project/") if relative.startswith("project/") else work / relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(base64.b64decode(encoded, validate=True))
    else:
        shutil.copytree(FIXTURE, project)
    if suite == "metadata":
        fixture = json.loads(Path("desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-project-v1.json").read_bytes())
        (project / ".gitignore").write_bytes(base64.b64decode(fixture["stages"]["config"]["project/.gitignore"], validate=True))
        metadata_folder = project / METADATA_TITLE.parent
        metadata_folder.mkdir(parents=True)
        for name in ("title.txt", "short_description.txt", "full_description.txt"):
            encoded = fixture["files"]["project/release/store/android/en-US/" + name]
            (metadata_folder / name).write_bytes(base64.b64decode(encoded, validate=True))
    call("/usr/bin/git", "-C", str(project), "init", "-b", "main")
    call("/usr/bin/git", "-C", str(project), "add", "--all")
    call("/usr/bin/git", "-C", str(project), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-m", "Original synthetic project")
    if suite in {"workspace", "projects", "reopen-projects"}:
        secondary = work / "MRK Verification Secondary"
        shutil.copytree(FIXTURE, secondary)
        (secondary / VERSION_FILE).write_bytes(b"VERSION_NAME=2.1.0\nBUILD_NUMBER=41\n")


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
            if region in {"Local Git action status", "Review local Git change"} and found["truncated"]:
                found = self.command("tree.snapshot", limit=800)
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

        def focused_root():
            nodes = self.command("tree.snapshot", limit=1)["nodes"]
            if len(nodes) == 1 and nodes[0]["id"] == f"mac:{pid}:0" and nodes[0]["role"] in ("window", "sheet"):
                return nodes[0] if nodes[0]["bounds"] else None
            return None

        root = until(focused_root, 4, "original-focused-app-window-or-sheet")
        snapshot, node = self.node(name, **selectors)
        need(node["id"].startswith(root["id"] + "."), "original-focused-app-window-or-sheet")
        window = root["bounds"]
        top = max(0, window["y"] + (35 if root["role"] == "window" else 3))
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
        for attempt in range(4):
            snapshot, node = self.reveal(name, category=category, contains=contains, region=region,
                                         enabled=True, actionable=True)
            try:
                self.command("element.click", snapshot_id=snapshot, id=node["id"])
                return
            except Exception as error:
                # The pinned action rejects a stale snapshot before sending
                # any pointer event. Let the AX tree settle and resolve the
                # exact same target again. Never repeat an uncertain click.
                payload = getattr(error, "payload", None)
                if (attempt == 3 or getattr(error, "status", None) != 409 or not isinstance(payload, dict) or
                    (payload.get("error") or {}).get("code") != "stale_snapshot"):
                    raise
                time.sleep(0.75)

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
            self.node(self.project_name or PAGE_HEADINGS["Overview"], category="heading")
            return
        self.choose_path(project, "Choose a mobile project folder")
        self.node(project.name, category="heading")
        self.project_name = project.name

    def choose_path(self, path, title):
        self.keys("command", "shift", "g")
        pid = self.payload_pid()

        def navigation_field():
            nodes = self.command("tree.snapshot", limit=40)["nodes"]
            if not nodes or nodes[0]["id"] != f"mac:{pid}:0" or nodes[0]["role"] != "sheet":
                return None
            matching_caption = any(node["visible"] and ("Go to Folder" in node["name"] or
                                   "Go to Folder" in node["text"] or node["text"] == "Go to:") for node in nodes)
            edits = [node for node in nodes if node["role"] == "textfield" and node["enabled"] and node["visible"]]
            need(len(edits) <= 1, "ambiguous-goto-input")
            return (edits[0], nodes) if matching_caption and edits else None

        until(navigation_field, 10, "exact-go-to-folder-sheet")
        self.keys("command", "a")
        self.command("text.insert", text=str(path))

        def completed_path():
            observation = navigation_field()
            if observation is None:
                return None
            field, nodes = observation
            return field["text"] == str(path) and any(
                node["role"] == "statictext" and path.name in (node["name"], node["text"])
                for node in nodes)

        until(completed_path, 10, "native-folder-completion-did-not-match-fixture")
        self.keys("return")

        def original_picker():
            nodes = self.command("tree.snapshot", limit=1)["nodes"]
            return len(nodes) == 1 and nodes[0]["id"] == f"mac:{pid}:0" and nodes[0]["role"] == "sheet" and \
                nodes[0]["name"].lower() == title.lower()

        until(original_picker, 5, "original-project-picker-did-not-resume")
        self.click("Open", category="button")

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

    def reopened_payload_pid(self, prior_pid):
        reply = call("/usr/bin/pgrep", "-f", PAYLOAD_PATTERN, check=False)
        need(reply.returncode in (0, 1), "reopened-payload-process-observation")
        if reply.returncode == 1:
            return None
        pids = reply.stdout.splitlines()
        need(len(pids) == 1, "ambiguous-reopened-payload")
        pid = int(pids[0])
        return pid if pid != prior_pid else None

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

        def resized_bounds():
            observed = window()["bounds"]
            if abs(observed["width"] - width) <= 1 and abs(observed["height"] - height) <= 1:
                return observed
            return None

        return until(resized_bounds, 3, "observed-window-size")


def open_session(work, action, *, previous=None, token_name="token"):
    def new_connection():
        found = [path for path in Path(os.environ["RUNNER_TEMP"]).glob("ui-session-*/connection.json")
                 if str(path) not in previous]
        need(len(found) <= 1, "unique-ui-session")
        return found[0] if found else None

    if previous is None:
        previous = set(json.loads((work / "previous-sessions.json").read_bytes()))
    path = until(new_connection, 260, "ui-action-never-ready")
    spec = importlib.util.spec_from_file_location("pinned_ui_client", action / "agent.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    connection = json.loads(path.read_bytes())
    need(connection["transport"] == "local" and connection["target"] == "macos", "loopback-only-session")
    need(re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", connection["url"]), "loopback-only-origin")
    return path, module.Client(connection, work / token_name)


def observe(work, action, media, suite):
    evidence = work / "evidence"
    manifest = json.loads((media / "RELEASE-MANIFEST.json").read_bytes())
    results = dict(sourceCommit=manifest["sourceCommit"], sourceTree=manifest["sourceTree"],
                   buildRun=manifest["buildRun"], carrierRun=manifest["carrierRun"],
                   manifestSha256=file_hash(media / "RELEASE-MANIFEST.json"),
                   packageSha256=manifest["packages"]["Install.pkg"]["sha256"],
                   removeSha256=manifest["packages"]["Remove.pkg"]["sha256"], suite=suite, scenarios={})
    scenarios = results["scenarios"]
    (evidence / "RESULT.json").write_text(json.dumps(results, indent=2) + "\n")
    connection, client = open_session(work, action)
    capabilities = json.loads(client.fetch("/v2/capabilities"))
    ui = UI(client, evidence, capabilities["screen"])
    project = work / ("MRK Verification iOS" if suite == "vault-profile" else "MRK Verification Android")
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

    def select_project(*, check_version=True):
        ui.page("Overview")
        ui.pick(project)
        ui.click("Project details & saved observations", contains=True)
        ui.node(str(project), category="statictext")
        if suite == "vault-profile":
            # The real iOS identity is also shown in Apple setup. This is a
            # readback under the exact selected path, so identical labels are
            # allowed. No action targets either result.
            ui.node("Configured iOS bundle ID", category="statictext")
            ui.command("element.wait", selector={"text": "org.example.mrk.observed", "role": "statictext", "visible": True},
                       state="present", timeout_ms=10000)
        else:
            ui.node("org.mrk.fixture", contains=True)
        if check_version:
            ui.click("Edit version & build number")
            ui.click("Open saved version editor", category="button")
            version = "Values: 1.2.3 · Build 7." if suite == "vault-profile" else "Values: 1.0.0 · Build 1."
            ui.node(version, category="statictext", contains=True)
        need(all(file_hash(project / name) == digest for name, digest in original.items()), "project-originals")

    def metadata_journey():
        def title():
            return ui.node("App title", category="textarea")[1]["text"]

        def edit_title(text):
            ui.click("App title", category="textarea")
            ui.keys("command", "a")
            ui.command("text.insert", text=text)
            need(title() == text, "exact-metadata-title-draft")

        initial = (project / METADATA_TITLE).read_text()
        replacement = "Fixture public UI title"
        ui.page("Store listing")
        ui.click("Load text", category="button")
        ui.snapshot("metadata-editor-loaded")
        need(title() == initial, "original-public-text-readback")
        edit_title("x" * 31)
        ui.click("Check text", category="button")
        ui.node("Needs changes", category="statictext")
        need(not ui.node("Review changes", category="button")[1]["enabled"], "over-limit-title-can-be-reviewed")
        need(file_hash(project / METADATA_TITLE) == original[METADATA_TITLE], "invalid-edit-changed-file")
        edit_title(replacement)
        ui.click("Check text", category="button")
        ui.node("Text looks good", category="statictext")
        ui.click("Review changes", category="button")
        ui.click("Save text…", category="button")
        ui.node("Save your Store text?", category="heading")
        ui.click("Keep reviewing", category="button")
        need(file_hash(project / METADATA_TITLE) == original[METADATA_TITLE], "cancelled-text-save-changed-file")
        ui.click("Save text…", category="button")
        ui.click("I reviewed the changes.", category="checkbox")
        ui.click("Save text", category="button")
        ui.node("Text saved", category="heading")
        need((project / METADATA_TITLE).read_bytes() == replacement.encode()
             and all(file_hash(project / name) == digest for name, digest in original.items() if name != METADATA_TITLE),
             "metadata-save-edited-unrelated-bytes")
        ui.click("Refresh text", category="button")
        need(title() == replacement, "saved-public-text-readback")

    def vault_journey():
        vault = Path.home() / "Library/Application Support/dev.mobile-release-kit.desktop/credential-vault-v1"
        controls = {"vault-lock": 0, "initialization-reservation": 48, "vault-header": 104}
        profile_file = work / "sources/synthetic.mobileprovision"
        profile_canary = b"private-envelope-only-canary"
        stored_profile = "Private input · Apple provisioning profile · item 1 · Synthetic profile input"

        def assert_no_header():
            need(not os.path.lexists(vault / "vault-header"), "vault-header-created-before-approval")

        def read_vault_state(*, with_profile=False):
            info = vault.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                 "new-vault-directory-custody")
            names = {path.name for path in vault.iterdir()}
            records = names - controls.keys()
            need(controls.keys() <= names and len(records) == int(with_profile) and
                 all(re.fullmatch(r"record-[0-9a-f]{32}", name) for name in records), "unexpected-vault-roster")
            leaves = {}
            for name in sorted(names):
                with os.fdopen(os.open(vault / name, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
                    item = os.fstat(stream.fileno())
                    need(stat.S_ISREG(item.st_mode) and item.st_nlink == 1 and item.st_uid == os.getuid() and
                         item.st_dev == info.st_dev and stat.S_IMODE(item.st_mode) == 0o600 and
                         (item.st_size == controls[name] if name in controls else 248 <= item.st_size <= 65536),
                         "vault-control-custody-" + name)
                    payload = stream.read(65537)
                    need(len(payload) == item.st_size and profile_canary not in payload, "vault-plaintext-or-size")
                    leaves[name] = (item.st_ino, hashlib.sha256(payload).hexdigest())
            return info.st_ino, leaves

        def await_status(label, *, region=None):
            def observed():
                rows = ui.command("tree.snapshot", limit=300)["nodes"]
                if region is not None:
                    parents = [row for row in rows if row["role"] == "group" and row["name"] == region and row["visible"]]
                    if len(parents) != 1:
                        return False
                    prefix = parents[0]["id"] + "."
                    rows = [row for row in rows if row["id"].startswith(prefix) and row["role"] == "statictext"]
                return any(label in (row["name"], row["text"]) for row in rows if row["visible"])
            until(observed, 45, "vault-state-" + label)

        def choose_option(control, value, moves):
            node = ui.node(control, category="popupbutton")[1]
            if node["text"] == value:
                return
            ui.click(control, category="popupbutton")
            ui.keys("home")
            for _ in range(moves):
                ui.keys("down")
            ui.keys("return")

            def selected():
                tree = ui.command("tree.snapshot", limit=300)
                matches = [row for row in tree["nodes"] if row["role"] == "popupbutton" and
                           row["name"] == control and row["visible"]]
                return len(matches) == 1 and matches[0]["text"] == value

            # The native menu closes before WebKit publishes the new AX value.
            # Read the original choice without sending another menu action.
            until(selected, 5, "wrong-vault-input-selection-" + control)

        def save_profile():
            ui.click("Submit current context", category="button")
            await_status("Context submitted · not yet policy-validated")
            choose_option("What would you like to provide?", "Apple provisioning profile", 4)
            ui.click("Select file…", category="button")
            ui.node("Choose a signing or iOS build-input file", contains=True)
            ui.choose_path(profile_file, "Choose a signing or iOS build-input file")
            await_status("selected", region="Private-input operation phase")
            await_status("choose-file", region="Private-input operation action")
            ui.edit("Vault label (optional)", "Synthetic profile input")
            ui.click("Prepare private review", category="button")
            await_status("File check")
            await_status("Configured only")
            await_status("CMS envelope only: this does not establish an Apple issuer, profile validity, team, bundle ID or signing permission.")
            await_status("Native validation: not run")
            await_status("Service validation: not run")
            await_status("Release readiness: unknown")
            ui.node("Save this encrypted input?", category="heading", region="Explicit private-input review")
            ui.click("Save encrypted copy", category="button", region="Explicit private-input review")
            await_status("Not assigned to the current draft")
            ui.node("1", category="statictext", region="Private-input record revision")
            state = read_vault_state(with_profile=True)
            facts["encryptedRevisionSavedAndUnauthorised"] = True
            save()

            def assignment_ready():
                tree = ui.command("tree.snapshot", limit=300)
                records = [row for row in tree["nodes"] if row["name"] == stored_profile and row["visible"]]
                if len(records) != 1:
                    return False
                prefix = records[0]["id"] + "."
                controls = [row for row in tree["nodes"] if row["id"].startswith(prefix)
                            and row["role"] == "button" and row["name"] == "Assess and assign…" and row["visible"]]
                return len(controls) == 1 and controls[0]["enabled"]

            # Saving the revision and clearing the original passive
            # saved-file check are separate. Do not re-submit either one.
            until(assignment_ready, 45, "original-saved-file-check-prevented-profile-assignment")
            ui.click("Assess and assign…", category="button", region=stored_profile)
            ui.node("Assign to this context", category="button")
            ui.click("Assign to this context", category="button", region="Explicit private-input review")
            await_status("Assigned to current submitted context")
            need(read_vault_state(with_profile=True) == state, "profile-bind-changed-encrypted-bytes")
            facts["envelopeSavedAndBound"] = True
            return state

        need(not os.path.lexists(vault), "existing-vault-is-outside-test-scope")
        facts = results["vaultLifecycle"] = {}
        ui.page("Signing & accounts")
        ui.click("Open encrypted vault", category="button")
        await_status("Encrypted vault · uninitialized")
        ui.click("Review vault initialization…", category="button")
        await_status("Create a new encrypted vault?")
        assert_no_header()
        ui.click("Discard review", category="button", region="Explicit private-input review")
        await_status("Storage closed")
        ui.node("discard", category="statictext", region="Private-input operation action")
        ui.node("known", category="statictext", region="Private-input operation settlement")
        assert_no_header()
        facts["cancelDidNotInitialize"] = True
        ui.click("Open encrypted vault", category="button")
        await_status("Encrypted vault · uninitialized")
        ui.click("Review vault initialization…", category="button")
        ui.click("Create encrypted vault", category="button", region="Explicit private-input review")
        await_status("Encrypted vault · unlocked")
        initial = read_vault_state()
        facts["createdOwnedEmptyVault"] = True
        with_profile = suite == "vault-profile"
        if with_profile:
            source_hash = file_hash(profile_file)
            choose_option("Platform", "iOS", 1)
            choose_option("Release stage", "Candidate / internal testing", 0)
            choose_option("Input purpose", "Build / signing only", 1)
            initial = save_profile()
        ui.click("Lock vault…", category="button")
        ui.click("Go back", category="button", region="Confirm private-input lock")
        await_status("Encrypted vault · unlocked")
        need(read_vault_state(with_profile=with_profile) == initial, "cancelled-lock-changed-vault")
        ui.click("Lock vault…", category="button")
        ui.click("Lock vault", category="button", region="Confirm private-input lock")
        await_status("Storage closed")
        need(read_vault_state(with_profile=with_profile) == initial, "lock-changed-vault-identity")
        facts["lockPreservedExactVault"] = True
        ui.click("Open encrypted vault", category="button")
        await_status("Encrypted vault · locked")
        ui.click("Unlock vault", category="button")
        await_status("Encrypted vault · unlocked")
        need(read_vault_state(with_profile=with_profile) == initial and
             all(file_hash(project / path) == digest for path, digest in original.items()),
             "reopen-changed-synthetic-vault-or-project")
        if with_profile:
            await_status("Not assigned to the current draft")
            ui.node("1", category="statictext", region="Private-input record revision")
            need(file_hash(profile_file) == source_hash, "original-profile-source-changed")
        facts["sameVaultReopenedAndUnlocked"] = True

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

    def cli_read_journey():
        receipts = results["installedCliReads"] = {}

        def request(command, *args, kind):
            process = call(str(CLI), command, *args, "--json", check=False)
            reply = json.loads(process.stdout)
            data = reply["response"]
            receipts[command] = {"return": process.returncode, "kind": data["kind"]}
            need(process.returncode == 0 and reply["version"] == 1 and data["kind"] == kind, f"cli-read-kind-{command}")
            return data["value"]

        def reject(command, *args, code, reason):
            process = call(str(CLI), command, *args, "--json", check=False)
            reply = json.loads(process.stdout)
            local = reply.get("ok") is False and reply.get("error") == reason
            remote = reply.get("response") == {"kind": "error", "value": reason}
            need(process.returncode == code and reply["version"] == 1 and (local or remote),
                 f"cli-refusal-{command}-{reason}")

        ui.page("Project settings")
        ui.click("Advanced · CLI / AI access", category="disclosuretriangle", contains=True)
        ui.click("Check access", category="button")
        ui.click("Allow selected project for 1 hour", category="button")
        ui.node("1 project was allowed at last check", category="statictext", contains=True)
        service = request("status", kind="info")
        # readOnly identifies the separate foreground history host. The live
        # Desktop host can service separately approved operations. This grant cannot.
        need(service["readOnly"] is False and service["cachedObservationsAreAuthority"] is False and
             service["readGrantAuthorizesExecution"] is False and service["localChecksRequireSeparateGrant"] is True and
             service["requiresRunningDesktop"] is True and
             0 < service["remainingAccessMs"] <= 3600000, "cli-session-read-only-contract")
        rows = request("projects", kind="projects")
        need(len(rows) == 1 and rows[0]["registeredInCurrentHost"] is True, "cli-only-current-project")
        project_id = rows[0]["projectId"]
        observation = request("observe", project_id, kind="observation")
        receipt = observation["observation"]["configuration"]
        need(observation["projectId"] == project_id and observation["registeredInCurrentHost"] is True and
             receipt == {"state": "format-valid", "bytes": (project / CONFIG_FILE).stat().st_size,
                         "sha256": original[CONFIG_FILE]}, "cli-saved-config-readback")
        journal = request("requests", project_id, kind="requests")
        need(journal["projectId"] == project_id and journal["doNotReplay"] is True and journal["requests"] == [],
             "cli-empty-request-discovery")
        tools = request("android-tools", project_id, kind="android-tools")
        need(tools["projectId"] == project_id and tools["projectCompatibility"] == "not-checked" and
             tools["freshness"] == "historical-not-revalidated", "cli-android-historical-labels")
        repository = request("repository", project_id, kind="repository")
        need(repository["projectId"] == project_id and repository["basis"] == "local-refs-no-fetch" and
             repository["freshness"] == "historical-not-revalidated", "cli-git-historical-labels")
        need(request("operations", project_id, kind="operations") == [], "cli-no-new-project-operations")
        reject("operation", project_id, "f" * 32, code=5, reason="conflict")
        reject("repository", project_id, "--fetch", code=2, reason="invalid_request")
        reject("observe", "not-a-project", code=2, reason="invalid_request")
        foreign = "f" * 32 if project_id != "f" * 32 else "e" * 32
        reject("observe", foreign, code=4, reason="access_denied")
        ui.click("Turn off access", category="button")
        ui.node("Off at last check", category="statictext", contains=True)
        for command in ("observe", "requests", "android-tools", "repository", "operations"):
            reject(command, project_id, code=4, reason="access_denied")
        need(all(file_hash(project / name) == digest for name, digest in original.items()), "cli-read-mutated-project")

    def project_switch_and_isolation():
        secondary = work / "MRK Verification Secondary"
        primary_before = {name: file_hash(project / name) for name in original}
        secondary_original = {path: file_hash(path) for path in secondary.rglob("*") if path.is_file()}

        def granted_project():
            reply = json.loads(call(str(CLI), "projects", "--json").stdout)["response"]
            need(reply["kind"] == "projects" and len(reply["value"]) == 1
                 and reply["value"][0]["registeredInCurrentHost"] is True, "exact-cli-project-scope")
            identity = reply["value"][0]["projectId"]
            need(re.fullmatch(r"[0-9a-f]{32}", identity) and identity != "0" * 32, "exact-cli-project-identity")
            return identity

        def access_panel():
            ui.page("Project settings")
            panel = ui.command("tree.snapshot", limit=300)
            if not any(node["role"] == "button" and node["name"] == "Check access" and
                       node["visible"] for node in panel["nodes"]):
                ui.click("Advanced · CLI / AI access", category="disclosuretriangle", contains=True)

        def observe_pending_state(stage):
            rows = ui.command("tree.snapshot", limit=300)["nodes"]
            markers = {"Apple setup · original operation retained", "Request acknowledgement is pending.",
                       "The outcome or cleanup is unconfirmed. Do not repeat registration or reconnect to dismiss it.",
                       "A local release-history intent or operation is retained. Cancel or finish it before other work.",
                       "A local Store access-check intent or operation is retained. Cancel or finish it before other work."}
            results.setdefault("unsubmittedOperationMarkers", {})[stage] = sorted(
                markers.intersection({node["name"] for node in rows} | {node["text"] for node in rows}))
            save()

        def grant_selected():
            access_panel()
            ui.click("Check access", category="button")
            ui.click("Allow selected project for 1 hour", category="button")
            ui.node("1 project was allowed at last check", category="statictext", contains=True)

        def require_denied(identity):
            denied = call(str(CLI), "observe", identity, "--json", check=False)
            reply = json.loads(denied.stdout)
            remote_error = reply.get("response") == {"kind": "error", "value": "access_denied"}
            local_error = (set(reply) == {"version", "ok", "error", "message"} and
                           reply["ok"] is False and reply["error"] == "access_denied")
            need(denied.returncode == 4 and reply["version"] == 1 and (remote_error or local_error),
                 "ungranted-project-observation-was-not-denied")

        def read_version(expected):
            tree = ui.command("tree.snapshot", limit=300)
            buttons = [node for node in tree["nodes"] if node["role"] == "button" and
                       node["name"] == "Open saved version editor" and node["visible"]]
            if not buttons:
                ui.click("Edit version & build number")
            ui.click("Open saved version editor", category="button")
            ui.node(expected, category="statictext", contains=True)

        checks = results["projectSwitchIsolation"] = {}
        observe_pending_state("before-grant")
        grant_selected()
        primary_id = granted_project()
        ui.page("Overview")
        ui.pick(secondary, cancel=True)
        ui.pick(secondary)
        observe_pending_state("after-secondary-selection")
        # Saved observation fields can change as selection settles. The grant
        # must retain the original project ID until another explicit Allow.
        need(granted_project() == primary_id, "switch-expanded-cli-authority")
        checks["retainedPrimaryGrantOnSwitch"] = True
        read_version("Values: 2.1.0 · Build 41.")
        checks["secondarySavedVersion"] = True
        grant_selected()

        def replacement():
            candidate = granted_project()
            return candidate if candidate != primary_id else None

        secondary_id = until(replacement, 10, "secondary-consent-did-not-replace-the-grant")
        require_denied(primary_id)
        checks["secondaryGrantReplacedPrimary"] = True
        ui.page("Overview")
        ui.pick(project)
        observe_pending_state("after-primary-selection")
        need(granted_project() == secondary_id, "reopen-expanded-cli-authority")
        require_denied(primary_id)
        expected_primary = "Values: 1.0.0 · Build 1." if suite == "projects" else "Values: 1.0.1 · Build 2."
        observe_pending_state("before-revocation")
        access_panel()
        ui.click("Turn off access", category="button")
        ui.node("Off at last check", category="statictext", contains=True)
        need(call(str(CLI), "status", "--json", check=False).returncode == 4, "switch-cli-grant-revocation")
        require_denied(secondary_id)
        checks["secondaryGrantRevokedAfterReturn"] = True
        save()
        ui.page("Overview")
        read_version(expected_primary)
        checks["primarySavedVersionAndDenialOnReturn"] = True
        observe_pending_state("after-return-version-read")
        need(all(file_hash(path) == digest for path, digest in secondary_original.items())
             and all(file_hash(project / name) == digest for name, digest in primary_before.items()), "switch-changed-fixture")
        checks["bothFixturesPreservedAndGrantRevoked"] = True
        need(not any(results["unsubmittedOperationMarkers"].values()), "unsubmitted-operations-blocked-workspace")

    def versions():
        nonlocal connection
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
        reopened_pid = until(lambda: ui.reopened_payload_pid(prior_pid), 12, "exact-reopened-payload-process")
        results["reopenedPayload"] = {"original": prior_pid, "reopened": reopened_pid}
        ui.image("before-reopened-driver")

        # The original action reported its original PID without a window after
        # Quit, even when the screen showed the newly opened app. Give the new
        # payload its own pinned session and rotate the local-only bearer.
        previous = {str(path) for path in Path(os.environ["RUNNER_TEMP"]).glob("ui-session-*/connection.json")}
        token = secrets.token_hex(32)
        (work / "reopen-token").write_text(token + "\n")
        request = work / "reopen-request.next"
        request.write_text(hashlib.sha256(token.encode("ascii")).hexdigest() + "\n")
        request.replace(work / "reopen-token-digest")
        (connection.parent / "stop").touch()
        connection, ui.client = open_session(work, action, previous=previous, token_name="reopen-token")

        end = time.monotonic() + 12
        need(ui.payload_pid() == reopened_pid, "reopened-payload-identity-changed")
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
        editor = "Open saved version editor"
        pending = "An original saved-file check is still pending. Wait for it to settle before starting another task."
        recovery = "A saved-file check needs attention"
        reopened_read = results["reopenedSavedFileCheck"] = {"observedPending": False, "editorEnabled": False}
        started = time.monotonic()

        def editor_ready():
            rows = ui.command("tree.snapshot", limit=300)["nodes"]
            labels = {label for row in rows for label in (row["name"], row["text"])}
            reopened_read["observedPending"] |= pending in labels
            need(recovery not in labels, "reopened-original-saved-file-cleanup-unknown")
            buttons = [row for row in rows if row["role"] == "button" and row["name"] == editor and row["visible"]]
            need(len(buttons) <= 1, "reopened-version-editor-ambiguous")
            return len(buttons) == 1 and buttons[0]["enabled"]

        # The selected workspace's passive observer can own a snapshot and
        # then a saved-version read sequentially, each with 10 s work and
        # 2 s cleanup. Wait for native admission without clicking or retrying.
        try:
            reopened_read["editorEnabled"] = until(editor_ready, 30, "reopened-version-editor-did-not-enable")
        finally:
            reopened_read["waitSeconds"] = round(time.monotonic() - started, 2)
        ui.click(editor, category="button")
        ui.node("Values: 1.0.1 · Build 2.", category="statictext", contains=True)
        need((project / VERSION_FILE).read_bytes() == expected
             and file_hash(project / CONFIG_FILE) == original[CONFIG_FILE], "reopened-saved-values")

    def git_observation():
        readme = project / "README.md"
        initial = readme.read_bytes()
        marker = b"\nSynthetic signed candidate UI verification.\n"
        readme.write_bytes(initial + marker)
        def git(*args):
            return call("/usr/bin/git", "-C", str(project), *args).stdout

        def wait_for_original_read(matches, stage):
            started = time.monotonic()

            def observe():
                tree = ui.command("tree.snapshot", limit=300)
                nodes = tree["nodes"]
                need(not any(node["role"] == "heading" and node["name"] in (
                    "Local Git read needs attention", "Local Git read did not complete") for node in nodes),
                    "original-local-git-read-refused")
                return tree if matches(nodes) else None

            # The Git reader owns a 45-second work and a 55-second hard
            # deadline. Observe the original operation without sending Start again.
            tree = until(observe, 55, "original-local-git-" + stage)
            results.setdefault("gitLocalReadSeconds", {})[stage] = round(time.monotonic() - started, 2)
            return tree

        def git_index_journey(head):
            review = "Review local Git change"
            reviewed = "I reviewed all listed files, including any contents not shown here."
            status_region = "Local Git action status"
            fact = results["gitIndex"] = {"originalStatusReads": 0, "visualStatusReads": 0,
                                          "reviewViewportScrolls": 0, "nativeReviewQueries": 0}

            def native_control(region, role, name, *, press=False):
                fact["nativeReviewQueries"] += 1
                checked = call("/usr/bin/swift", str(CONSOLE_OCR), "git-review",
                               str(ui.payload_pid()), region, role, name, "press" if press else "inspect",
                               timeout=15, check=False)
                need(checked.returncode == 0 and len(checked.stdout) <= 1024, "git-native-review-query-failed")
                observed = json.loads(checked.stdout)
                need(observed.get("error") not in {"ax-unavailable", "not-frontmost", "window", "window-bound", "region-bound"},
                     "git-native-review-unavailable-" + str(observed.get("error")))
                need("error" not in observed and observed["regions"] <= 1 and observed["matches"] <= 1,
                     "git-native-review-query-ambiguous")
                if press:
                    need(observed.get("pressed") is True, "git-native-review-action-not-confirmed")
                return observed

            def read_visible_original_status(tree):
                # The macOS driver caps its platform tree at 300 nodes.
                # An omitted Check action is still usable when the original
                # panel is visible. Only target its read-only button.
                root = tree["nodes"][0]
                need(root["id"] == f"mac:{ui.payload_pid()}:0" and root["role"] == "window" and root["bounds"],
                     "git-status-not-original-window")
                bounds = root["bounds"]
                frame = ui.image(f"git-original-status-{fact['visualStatusReads']}")
                rows = json.loads(call("/usr/bin/swift", str(CONSOLE_OCR), str(frame), timeout=20).stdout)
                matches = [[row for row in rows if row["text"] == label] for label in
                           ("Git action is still running", "Check action", "Stop original action")]
                if any(len(match) != 1 for match in matches):
                    return False
                title, check, stop = [match[0] for match in matches]
                x = round(check["x"] * ui.screen["width"])
                y = round(check["y"] * ui.screen["height"])
                need(bounds["x"] + 200 < x < bounds["x"] + bounds["width"] - 8 and
                     bounds["y"] + 35 < y < min(bounds["y"] + bounds["height"] - 8, ui.screen["height"] - 65)
                     and 0 < check["y"] - title["y"] < 0.2
                     and abs(check["y"] - stop["y"]) < 0.02 and 0 < stop["x"] - check["x"] < 0.25,
                     "git-original-status-button-geometry")
                focused = ui.command("tree.snapshot", limit=1)["nodes"]
                need(len(focused) == 1 and focused[0]["id"] == root["id"] and focused[0]["bounds"] == bounds,
                     "git-status-window-changed")
                ui.command("pointer.click", x=x, y=y)
                fact["visualStatusReads"] += 1
                return True

            def scroll_visible_review(tree):
                root = tree["nodes"][0]
                need(root["id"] == f"mac:{ui.payload_pid()}:0" and root["role"] == "window" and root["bounds"],
                     "git-review-not-original-window")
                frame = ui.image(f"git-review-viewport-{fact['reviewViewportScrolls']}")
                rows = json.loads(call("/usr/bin/swift", str(CONSOLE_OCR), str(frame), timeout=20).stdout)
                labels = ("Review before changing Git", "Close review, keep draft")
                matches = [[row for row in rows if row["text"] == label] for label in labels]
                if any(len(match) != 1 for match in matches):
                    return False
                title, close = (match[0] for match in matches)
                x = round(close["x"] * ui.screen["width"])
                y = round(close["y"] * ui.screen["height"])
                bounds = root["bounds"]
                if not (bounds["x"] + 200 < x < bounds["x"] + bounds["width"] - 8 and
                        bounds["y"] + 35 < y < min(bounds["y"] + bounds["height"] - 8, ui.screen["height"] - 65)
                        and 0 < close["y"] - title["y"] < 0.2):
                    return False
                focused = ui.command("tree.snapshot", limit=1)["nodes"]
                need(len(focused) == 1 and focused[0]["id"] == root["id"] and focused[0]["bounds"] == bounds,
                     "git-review-window-changed")
                ui.command("pointer.scroll", x=x, y=y, dy=6)
                return True

            def await_heading(name):
                next_read = time.monotonic() + 2
                review_scrolls = 0

                def observe():
                    nonlocal next_read, review_scrolls
                    tree = ui.command("tree.snapshot", limit=300)
                    rows = tree["nodes"]
                    headings = {row["name"] for row in rows if row["role"] == "heading" and row["visible"]}
                    need(not headings.intersection({"Git action needs attention", "Git recovery is needed",
                                                   "Git action did not complete"}), "git-index-original-action-refused")
                    if name in headings:
                        return True
                    if (name in {"Review files to stage", "Review files to unstage"} and
                            "Review before changing Git" in headings and review_scrolls < 3):
                        # The original review card follows the status region and
                        # can be clipped below the hosted runner's viewport.
                        # Use its visible status button only as a scroll anchor.
                        root = rows[0]
                        anchors = [row for row in rows if row["name"] == "Close review, keep draft" and
                                   row["role"] == "button" and row["visible"] and row["bounds"]]
                        if len(anchors) == 1 and root["id"] == f"mac:{ui.payload_pid()}:0" and root["bounds"]:
                            anchor = anchors[0]
                            bounds, box = root["bounds"], anchor["bounds"]
                            x, y = box["x"] + box["width"] // 2, box["y"] + box["height"] // 2
                            if (anchor["id"].startswith(root["id"] + ".") and
                                    bounds["x"] + 200 < x < bounds["x"] + bounds["width"] - 8 and
                                    bounds["y"] + 35 < y < min(bounds["y"] + bounds["height"] - 8,
                                                               ui.screen["height"] - 65)):
                                ui.command("pointer.scroll", x=x, y=y, dy=6)
                                review_scrolls += 1
                                fact["reviewViewportScrolls"] += 1
                                return False
                    # The mutation controller's initial acknowledgement can
                    # be active. Check the original action as the UI directs.
                    if time.monotonic() >= next_read:
                        if tree["truncated"]:
                            region = review if name in {"Review files to stage", "Review files to unstage"} else status_region
                            if native_control(region, "AXHeading", name)["matches"] == 1:
                                return True
                            if region == status_region:
                                check = native_control(status_region, "AXButton", "Check action")
                                if check["matches"] == 1 and check.get("enabled") is True:
                                    # Apply can scroll the original status out of
                                    # view. This requests only the original read.
                                    native_control(status_region, "AXButton", "Check action", press=True)
                                    fact["originalStatusReads"] += 1
                                    next_read = time.monotonic() + 5
                                    return False
                        if (tree["truncated"] and name in {"Review files to stage", "Review files to unstage"}
                                and review_scrolls < 3 and scroll_visible_review(tree)):
                            fact["reviewViewportScrolls"] += 1
                            review_scrolls += 1
                            return False
                        if any(row["name"] == "Check action" and row["role"] == "button" and
                               row["enabled"] and row["visible"] for row in rows):
                            ui.click("Check action", category="button", region="Local Git action status")
                            fact["originalStatusReads"] += 1
                        elif tree["truncated"]:
                            if fact["visualStatusReads"] < 3 and read_visible_original_status(tree):
                                fact["originalStatusReads"] += 1
                        next_read = time.monotonic() + 5
                    return False
                until(observe, 60, "git-index-" + name)

            def verify_change(staged):
                need(git("rev-parse", "HEAD") == head and readme.read_bytes() == initial + marker,
                     "git-index-changed-head-or-working-file")
                expected = b"README.md\n" if staged else b""
                need(git("diff", "--cached", "--name-only") == expected, "git-index-unexpected-staged-custody")
                if staged:
                    need(git("show", ":README.md") == initial + marker, "git-index-wrong-staged-bytes")

            def index_readback(expected):
                try:
                    return git("diff", "--cached", "--name-only") == expected
                except (OSError, subprocess.SubprocessError):
                    return None

            def press_after_settlement(region, name):
                until(lambda: native_control(region, "AXButton", name).get("enabled") is True,
                      15, "git-control-not-enabled-" + name)
                native_control(region, "AXButton", name, press=True)

            ui.click("Check local Git actions", category="button", region="Local Git action status")
            ui.click("Review files to stage", category="button")
            await_heading("Review files to stage")
            need(native_control(review, "AXStaticText", "README.md")["matches"] == 1, "git-stage-review-path")
            apply = native_control(review, "AXButton", "Stage these files")
            need(apply["matches"] == 1 and apply["enabled"] is False,
                 "git-index-apply-enabled-without-consent")
            native_control(status_region, "AXButton", "Close review, keep draft", press=True)
            verify_change(False)
            fact["cancelPreservedIndexAndHead"] = True
            ui.click("Review files to stage", category="button")
            await_heading("Review files to stage")
            need(native_control(review, "AXStaticText", "README.md")["matches"] == 1, "git-stage-review-path")
            need(native_control(review, "AXCheckBox", reviewed).get("checked") is False, "git-stage-consent-starts-clear")
            native_control(review, "AXCheckBox", reviewed, press=True)
            need(native_control(review, "AXCheckBox", reviewed).get("checked") is True, "git-stage-consent-readback")
            native_control(review, "AXButton", "Stage these files", press=True)
            fact["stagePressConfirmed"] = True
            try:
                await_heading("Selected files staged")
            finally:
                fact["stageIndexObserved"] = index_readback(b"README.md\n")
            verify_change(True)
            fact["onlyReviewedBlobStaged"] = True
            press_after_settlement("Local Git changes", "Refresh changes")
            until(lambda: native_control("Local Git read status", "AXHeading", "Local Git read finished")["matches"] == 1,
                  55, "git-index-original-stage-readback")
            press_after_settlement(status_region, "Check local Git actions")
            press_after_settlement("Local Git changes", "Review files to unstage")
            await_heading("Review files to unstage")
            need(native_control(review, "AXStaticText", "README.md")["matches"] == 1, "git-unstage-review-path")
            need(native_control(review, "AXCheckBox", reviewed).get("checked") is False, "git-unstage-consent-starts-clear")
            native_control(review, "AXCheckBox", reviewed, press=True)
            need(native_control(review, "AXCheckBox", reviewed).get("checked") is True, "git-unstage-consent-readback")
            native_control(review, "AXButton", "Unstage these files", press=True)
            fact["unstagePressConfirmed"] = True
            try:
                await_heading("Selected files unstaged")
            finally:
                fact["unstageIndexObserved"] = index_readback(b"")
            verify_change(False)
            fact["unstagePreservedHeadAndWorktree"] = True

        before = git("status", "--porcelain=v1")
        head = git("rev-parse", "HEAD")
        need(before == b" M README.md\n", "exact-synthetic-worktree-change")
        try:
            ui.page("GitHub")
            ui.click("Connect", category="radiobutton", region="GitHub tasks")
            ui.click("Check local Git access", category="button")
            ui.node("Local Git reader available", category="heading")
            ui.click("Refresh changes", category="button")
            wait_for_original_read(lambda nodes: any(node["role"] == "heading" and
                node["name"] == "Local Git read finished" for node in nodes), "observation")
            _, changes = ui.reveal("Source changes", category="heading")
            bounds = changes["bounds"]
            ui.command("pointer.scroll", x=bounds["x"] + bounds["width"] // 2,
                       y=bounds["y"] + bounds["height"] // 2, dy=6)
            tree = ui.command("tree.snapshot", limit=300)
            (evidence / "git-source-changes-tree.json").write_text(json.dumps(tree, indent=2) + "\n")
            nodes = tree["nodes"]
            pid = ui.payload_pid()
            need(nodes and nodes[0]["id"] == f"mac:{pid}:0" and nodes[0]["role"] == "window",
                 "exact-source-changes-window")
            table, = [node for node in nodes if node["role"] == "table" and
                      node["name"].startswith("Choose files to inspect.")]
            # WebKit exposes each cell under its row and again under its column.
            # Select the checkbox in the actual row for the one changed file.
            row, = [node for node in nodes if node["role"] == "row" and node["id"].startswith(table["id"] + ".") and
                    any(item["id"].startswith(node["id"] + ".") and "README.md" in (item["name"], item["text"])
                        for item in nodes)]
            select = [node for node in nodes if node["role"] == "checkbox" and node["visible"] and node["enabled"] and
                      node["id"].startswith(row["id"] + ".") and node["name"] == "Select README.md"]
            need(len(select) == 1 and select[0]["bounds"], "exact-readme-row-checkbox")
            box, window = select[0]["bounds"], nodes[0]["bounds"]
            x, y = box["x"] + box["width"] // 2, box["y"] + box["height"] // 2
            need(window["x"] < x < window["x"] + window["width"] and
                 window["y"] + 35 < y < min(window["y"] + window["height"] - 8, ui.screen["height"] - 65),
                 "readme-checkbox-outside-app-viewport")
            ui.command("element.click", snapshot_id=tree["snapshot_id"], id=select[0]["id"])
            if suite == "git-index":
                # The workspace journey already verifies the working-file diff.
                # Leave that extra AX subtree closed for the separate index test.
                git_index_journey(head)
                return
            ui.click("Working changes", category="button")
            added_line = "+" + marker.strip().decode()
            diff = wait_for_original_read(lambda nodes: any(added_line in node["text"].splitlines()
                or added_line in node["name"].splitlines() for node in nodes), "working-diff")
            (evidence / "git-working-diff-tree.json").write_text(json.dumps(diff, indent=2) + "\n")
            ui.reveal("Working-file changes", category="heading")
            need(git("status", "--porcelain=v1") == before and git("rev-parse", "HEAD") == head
                 and git("diff", "--cached", "--name-only") == b"", "git-read-affected-repository")
        finally:
            need(readme.read_bytes() == initial + marker, "git-read-changed-the-synthetic-input")
            readme.write_bytes(initial)

    def window_layouts():
        screen = json.loads(client.fetch("/v2/capabilities"))["screen"]
        # Leave room for the title bar position and the Dock's reserved area.
        width, height = min(screen["width"] - 32, 1180), min(screen["height"] - 120, 740)
        # The native payload enforces a minimum height of 640 points.
        if width < 980 or height < 648:
            raise Blocked("The synthetic console is too small for two readable window sizes")
        results["windowBounds"] = []
        for width, height in ((width - 40, max(640, height - 20)), (width, height)):
            results["windowBounds"].append(ui.resize(width, height))
            ui.page("Overview")
            ui.page("Project settings")
            ui.image(f"settings-{width}x{height}")

    try:
        if suite == "reopen-projects":
            if (scenario("native-console-admission", lambda: ui.record_session("console-admission", start_observation)) and
                scenario("project-picker-and-saved-config", select_project) and
                scenario("version-cancel-save-quit-reopen", versions)):
                scenario("project-switch-and-cli-isolation", project_switch_and_isolation)
            return 0 if scenarios.keys() == SUITE_SCENARIOS[suite] and all(row["status"] == "Passed" for row in scenarios.values()) else 1
        independent_journeys = {
            "metadata": ("metadata-negative-cancel-save-readback", metadata_journey),
            "projects": ("project-switch-and-cli-isolation", project_switch_and_isolation),
            "cli-read": ("installed-cli-read-data-and-refusals", cli_read_journey),
            "git-index": ("git-index-review-stage-unstage", git_observation),
            "vault-lifecycle": ("vault-cancel-lock-reopen", vault_journey),
            "vault-profile": ("vault-profile-save-bind-unlock", vault_journey),
        }
        if suite in independent_journeys:
            name, journey = independent_journeys[suite]
            if scenario("native-console-admission", lambda: ui.record_session("console-admission", start_observation)):
                if scenario("project-picker-and-saved-config", lambda: select_project(check_version=suite not in {"cli-read", "vault-profile"})):
                    scenario(name, journey)
                else:
                    scenarios[name] = dict(status="Blocked", reason="Fixture project selection failed")
                    save()
            return 0 if scenarios.keys() == SUITE_SCENARIOS[suite] and all(row["status"] == "Passed" for row in scenarios.values()) else 1
        if scenario("native-console-admission", lambda: ui.record_session("console-admission", start_observation)):
            scenario("cold-runtime-and-cli-denial", startup)
            scenario("cancel-native-project-picker", cancel_picker)
            selected = scenario("project-picker-and-saved-config", select_project)
            for label, page in NAVIGATION_SCENARIOS.items():
                scenario(label, lambda page=page: ui.page(page))
            if selected:
                scenario("cli-grant-and-revoke", permission_lifecycle)
                scenario("git-local-diff-and-no-side-effects", git_observation)
            else:
                scenarios["cli-grant-and-revoke"] = dict(status="Blocked", reason="Fixture project selection failed")
                scenarios["version-cancel-save-quit-reopen"] = dict(status="Blocked", reason="Fixture project selection failed")
                scenarios["git-local-diff-and-no-side-effects"] = dict(status="Blocked", reason="Fixture project selection failed")
                scenarios["project-switch-and-cli-isolation"] = dict(status="Blocked", reason="Fixture project selection failed")
            scenario("window-layouts", window_layouts)
            if selected:
                if scenario("version-cancel-save-quit-reopen", versions):
                    scenario("project-switch-and-cli-isolation", project_switch_and_isolation)
                else:
                    scenarios["project-switch-and-cli-isolation"] = dict(status="Blocked", reason="Saved project reopening failed")
        else:
            for name in ("project-picker-and-saved-config", "cli-grant-and-revoke", "workspace-navigation",
                         "version-cancel-save-quit-reopen", "window-layouts", "git-local-diff-and-no-side-effects",
                         "project-switch-and-cli-isolation"):
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
    parser.add_argument("--suite", choices=SUITE_SCENARIOS, default="workspace")
    args = parser.parse_args()
    if args.mode == "install":
        install(args.media, args.work, args.suite)
        return 0
    if args.mode == "require":
        verify_observation(args.work, args.media, args.suite)
        return 0
    return observe(args.work, args.action, args.media, args.suite)


if __name__ == "__main__":
    raise SystemExit(main())
