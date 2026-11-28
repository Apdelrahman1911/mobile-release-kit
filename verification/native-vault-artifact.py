"""Exercise the installed release through a pinned ui-test-actions loopback session."""
import argparse
import base64
import errno
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
import sys
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

import zipfile

VAULT = "vault-restart-stable"
SCENARIOS = {VAULT: "vault-restart-reassess", "artifact-synthetic": "artifact-picker-and-byte-inspection"}
BASE_SCENARIOS = {"native-console-admission", "project-picker-and-saved-config"}
SUITE_SCENARIOS = {suite: BASE_SCENARIOS | {scenario} for suite, scenario in SCENARIOS.items()}


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


def install_current_media(media, work):
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
            if (region in {"Local Git action status", "Review local Git change", "Set up local Git", "Review local Git initialization", "Project initialization", "Switch local branch", "Rename current local branch", "Local branches", "Local Git read status", "Localized screenshot and image import", "Original localized-image operation", "Fresh local action confirmation", "Local Git changes", "Review new local branch", "Review local branch rename", "Review local branch switch", "Explicit private-input review",
                           "Encrypted backup and restore", "GitHub connection and observations", "Inspect first, then review what can safely be recovered", "Inspect selected artifact bytes", "Artifact byte inspection result",
                           "Confirm selected artifact inspection"} or region.startswith("Private input · ")) and found["truncated"]:
                found = self.command("tree.snapshot", limit=800)
            parents = [row for row in found["nodes"] if row["name"] == region and row["visible"]]
            if region in {"Inspect first, then review what can safely be recovered", "Local branches", "Review new local branch",
                          "Review local branch rename", "Review local branch switch", "Review local Git initialization"}:
                parents = [row for row in parents if row["role"] == "group"]
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



def install(media, work, suite):
    install_current_media(media, work)
    project = work / ("MRK Verification iOS" if suite == VAULT else "MRK Verification Android")
    if suite == VAULT:
        fixture_file = Path("desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-persistence-v1.json")
        fixture = json.loads(fixture_file.read_bytes())
        for relative, encoded in fixture["files"].items():
            if relative.startswith("project/") or relative == "sources/synthetic.mobileprovision":
                target = project / relative.removeprefix("project/") if relative.startswith("project/") else work / relative
                need(target.resolve().is_relative_to(work.resolve()), "fixture-path-outside-work")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(base64.b64decode(encoded, validate=True))
    else:
        shutil.copytree(FIXTURE, project)
        with zipfile.ZipFile(work / "synthetic.aab", "w") as archive:
            for name in ("BundleConfig.pb", "base/manifest/AndroidManifest.xml", "base/dex/classes.dex"):
                entry = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(entry, b"synthetic ZIP structure only; no DEX, manifest or signature")
        (work / "malformed.aab").write_bytes(b"qualification fixture without any ZIP structure")
    call("/usr/bin/git", "-C", str(project), "init", "-b", "main")
    call("/usr/bin/git", "-C", str(project), "add", "--all")
    call("/usr/bin/git", "-C", str(project), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-m", "Original synthetic project")


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
    project = work / ("MRK Verification iOS" if suite == VAULT else "MRK Verification Android")
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

    def select_project():
        ui.page("Overview")
        ui.pick(project)
        ui.click("Project details & saved observations", contains=True)
        ui.node(str(project), category="statictext")
        if suite == VAULT:
            # The real iOS identity is also shown in Apple setup. This is a
            # readback under the exact selected path, so identical labels are
            # allowed. No action targets either result.
            ui.node("Configured iOS bundle ID", category="statictext")
            ui.command("element.wait", selector={"text": "org.example.mrk.observed", "role": "statictext", "visible": True},
                       state="present", timeout_ms=10000)
        else:
            ui.node("org.mrk.fixture", contains=True)

        need(all(file_hash(project / name) == digest for name, digest in original.items()), "project-originals")

    def vault_journey():
        nonlocal connection
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
                tree = ui.command("tree.snapshot", limit=800)
                visible = [row for row in tree["nodes"] if row["visible"]]

                def known_group(group, expected):
                    parents = [row["id"] + "." for row in visible if row["role"] == "group" and row["name"] == group]
                    return len(parents) == 1 and any(
                        row["id"].startswith(parents[0]) and row["role"] == "statictext" and
                        expected in (row["name"], row["text"]) for row in visible)

                facts["saveAdmission"] = {
                    "commit": known_group("Private-input operation action", "commit"),
                    "idle": known_group("Private-input operation phase", "idle"),
                    "settled": known_group("Private-input operation settlement", "known"),
                    "applied": known_group("Where your keys are kept effect", "known-applied"),
                    "durable": known_group("Where your keys are kept durability", "confirmed"),
                    "cleaned": known_group("Where your keys are kept cleanup", "known"),
                }
                if not all(facts["saveAdmission"].values()):
                    return False
                records = [row for row in tree["nodes"] if row["name"] == stored_profile and row["visible"]]
                if len(records) != 1:
                    return False
                prefix = records[0]["id"] + "."
                controls = [row for row in tree["nodes"] if row["id"].startswith(prefix)
                            and row["role"] == "button" and row["name"] == "Assess and assign…" and row["visible"]]
                return len(controls) == 1 and controls[0]["enabled"]

            # Saving the revision and clearing the original passive
            # saved-file check are separate. Do not re-submit either one.
            try:
                until(assignment_ready, 45, "original-record-save-did-not-confirm-durability-and-cleanup")
            finally:
                save()
            ui.click("Assess and assign…", category="button", region=stored_profile)

            def bind_preview():
                tree = ui.command("tree.snapshot", limit=800)
                labels = {value for row in tree["nodes"] if row["visible"] for value in (row["name"], row["text"])}
                facts["firstAssignment"] = {
                    "nativeBusy": "asset_busy" in labels,
                    "confirmation": "Assign this record to the submitted context?" in labels,
                    "statusRequired": "A current native session status is required. Check status before continuing." in labels,
                }
                if facts["firstAssignment"]["nativeBusy"]:
                    need(read_vault_state(with_profile=True) == state, "refused-assignment-changed-vault")
                    facts["busyRefusalPreservedVault"] = True
                    ui.snapshot("original-assignment-refusal")
                    raise AssertionError("original-native-record-assessment-refused-asset_busy")
                return facts["firstAssignment"]["confirmation"]

            until(bind_preview, 35, "original-assignment-preview-not-observed")

            def enabled_confirmation():
                nodes = ui.command("tree.snapshot", limit=800)["nodes"]
                groups = [row["id"] + "." for row in nodes if row["visible"] and
                          row["name"] == "Explicit private-input review"]
                if len(groups) != 1:
                    return False
                buttons = [row for row in nodes if row["id"].startswith(groups[0]) and row["visible"] and
                           row["role"] == "button" and row["name"] == "Assign to this context"]
                facts["confirmationAdmission"] = {"matchingControls": len(buttons),
                                                  "enabled": len(buttons) == 1 and buttons[0]["enabled"]}
                return facts["confirmationAdmission"]["enabled"]

            try:
                until(enabled_confirmation, 30, "exact-assignment-confirmation-never-became-enabled")
            finally:
                save()
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
        with_profile = True
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
        if suite in {"vault-upgrade", "vault-restart", "vault-restart-stable"}:
            prior_pid = ui.payload_pid()
            ui.keys("command", "q")
            ui.node("Quit and discard unsaved drafts?", contains=True)
            ui.click("Quit", category="button")
            until(lambda: call("/usr/bin/pgrep", "-f", PAYLOAD_PATTERN, check=False).returncode == 1,
                  22, "predecessor-not-quit")
            need(read_vault_state(with_profile=True) == initial, "predecessor-quit-changed-vault")
            facts["normalQuitRetainedRecord"] = True
            save()
            call("/usr/bin/open", "-a", str(APP))
            reopened_pid = until(lambda: ui.reopened_payload_pid(prior_pid), 18, "exact-updated-payload")
            previous = {str(path) for path in Path(os.environ["RUNNER_TEMP"]).glob("ui-session-*/connection.json")}
            token = secrets.token_hex(32)
            (work / "reopen-token").write_text(token + "\n")
            request = work / "reopen-request.next"
            request.write_text(hashlib.sha256(token.encode("ascii")).hexdigest() + "\n")
            request.replace(work / "reopen-token-digest")
            (connection.parent / "stop").touch()
            connection, ui.client = open_session(work, action, previous=previous, token_name="reopen-token")
            need(ui.payload_pid() == reopened_pid, "updated-app-changed-before-observation")
            ui.project_name = None
            ui.click("Overview", category="button")
            known_headings = {PAGE_HEADINGS["Overview"], project.name}
            def project_state():
                names = {row["name"] for row in ui.command("tree.snapshot", limit=300)["nodes"]
                         if row["role"] == "heading" and row["visible"] and row["name"] in known_headings}
                need(len(names) <= 1, "ambiguous-updated-project")
                return next(iter(names)) if names else None
            if until(project_state, 20, "updated-project-overview") == PAGE_HEADINGS["Overview"]:
                ui.pick(project)
            else:
                ui.project_name = project.name
            ui.page("Signing & accounts")
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
        if suite in {"vault-upgrade", "vault-restart", "vault-restart-stable"}:
            # Unlock must authenticate the existing encrypted record with
            # the preserved Keychain key. Inspect it without reassigning it.
            choose_option("Platform", "iOS", 1)
            choose_option("Release stage", "Candidate / internal testing", 0)
            choose_option("Input purpose", "Build / signing only", 1)
            if suite != "vault-restart-stable":
                ui.click("Submit current context", category="button")
            await_status("Context submitted · not yet policy-validated")
            if suite == "vault-restart-stable":
                facts["oneOrdinaryContextAfterScopeChange"] = True
                ui.click("Check storage status", category="button")
                await_status("Context submitted · not yet policy-validated")
                await_status("known", region="Private-input operation settlement")
                await_status("idle", region="Private-input operation phase")
                await_status("unlock", region="Private-input operation action")
                ui.snapshot("reopened-vault-before-assessment")
            ui.click("Assess and assign…", category="button", region=stored_profile)
            await_status("CMS envelope only: this does not establish an Apple issuer, profile validity, team, bundle ID or signing permission.")
            ui.node("Assign this record to the submitted context?", category="heading", region="Explicit private-input review")
            facts["sameRecordReassessedFromDisk"] = True
            save()
            ui.click("Discard review", category="button", region="Explicit private-input review")
            await_status("Not assigned to the current draft")
            need(read_vault_state(with_profile=True) == initial, "assessment-changed-original-encrypted-record")
            facts["originalRecordDecryptedForEnvelopeAssessmentAndKeptUnassigned"] = True

    def aab_readback():
        ui.page("Build files")
        consent = "Confirm selected artifact inspection"
        report = "Artifact byte inspection result"
        title = "Choose an Android App Bundle to inspect"
        facts = results["artifactInspection"] = {}

        def inspect(path):
            input_digest = file_hash(path)
            ui.click("Choose AAB", category="button")
            ui.node(title, contains=True)
            ui.choose_path(path, title)
            ui.node(path.name, category="statictext", contains=True)
            ui.click("Review artifact inspection", category="button")
            ui.node("Inspect these selected inputs?", category="heading")
            _, start = ui.node("Inspect selected bytes", category="button", region=consent)
            need(not start["enabled"], "artifact-inspection-enabled-without-consent")
            ui.click("I understand this inspects only the selected bytes", category="checkbox", contains=True, region=consent)
            ui.click("Inspect selected bytes", category="button", region=consent)
            until(lambda: any(row["visible"] and row["name"] == "Recorded artifact checks" for row in
                  ui.command("tree.snapshot", limit=800)["nodes"]), 55, "original-artifact-check-report-unavailable")
            ui.node(input_digest, category="statictext", contains=True, region=report)
            need(file_hash(path) == input_digest and
                 all(file_hash(project / name) == value for name,value in original.items()),
                 "read-only-artifact-inspection-mutated-input")
            nodes = ui.command("tree.snapshot", limit=800)["nodes"]
            parents = [row["id"] + "." for row in nodes if row["visible"] and row["name"] == report]
            need(len(parents) == 1, "ambiguous-artifact-report")
            panel = [row for row in nodes if row["visible"] and row["id"].startswith(parents[0])]
            checks = ("Observed byte identity", "Package or archive structure", "Cryptographic signature")
            statuses = {"Passed this check", "Failed this check", "Unavailable / not established", "Not applicable"}
            result = {}
            for row in (row for row in panel if row["role"] == "row"):
                values = {value for item in panel if item["id"].startswith(row["id"] + ".")
                          for value in (item["name"], item["text"])}
                for check in set(checks) & values:
                    matches = values & statuses
                    need(len(matches) == 1 and check not in result, "ambiguous-artifact-check")
                    result[check], = matches
            need(set(result) == set(checks), "missing-artifact-check")
            return result

        ui.click("Choose AAB", category="button")
        ui.node(title, contains=True)
        ui.click("Cancel", category="button")
        _, review = ui.node("Review artifact inspection", category="button")
        need(not review["enabled"], "cancelled-artifact-picker-retained-inspection-input")
        facts["pickerCancelLeftNoInput"] = True
        save()

        def ready_to_choose():
            rows = ui.command("tree.snapshot", limit=600)["nodes"]
            buttons = [row for row in rows if row["visible"] and row["name"]=="Choose AAB" and row["role"]=="button"]
            return len(buttons)==1 and buttons[0]["enabled"]

        # Read the original operation through its supported UI. Do not
        # synthesize cancellation settlement or start a second picker early.
        _, status = ui.node("Check artifact status", category="button")
        if status["enabled"] and not ready_to_choose():
            ui.click("Check artifact status", category="button")
        if not ready_to_choose():
            ui.page("Signing & accounts")
            _, status = ui.node("Check storage status", category="button")
            if status["enabled"]:
                ui.click("Check storage status", category="button")
            ui.page("Build files")
        until(ready_to_choose, 35, "artifact-cancel-original-asset-session-did-not-settle")
        facts["reselectionAdmittedAfterOriginalStatus"] = True
        rows = inspect(work / "synthetic.aab")
        facts["syntheticAabChecks"] = rows
        save()
        need(rows["Observed byte identity"] == "Passed this check" and
             rows["Package or archive structure"] == "Passed this check" and
             rows["Cryptographic signature"] != "Passed this check", "synthetic-aab-structure-or-signature")
        facts["syntheticAabStructureInspected"] = True
        save()
        ui.click("Discard selection and review", category="button")
        _, review = ui.node("Review artifact inspection", category="button")
        need(not review["enabled"], "discard-retained-original-review")
        rows = inspect(work / "malformed.aab")
        facts["malformedAabChecks"] = rows
        save()
        need(rows["Package or archive structure"] == "Failed this check" and
             rows["Cryptographic signature"] != "Passed this check", "malformed-archive-not-reported-as-failed")
        facts["malformedAabRejectedWithoutChangingInputs"] = True

    try:
        if scenario("native-console-admission", start_observation) and scenario("project-picker-and-saved-config", select_project):
            scenario(SCENARIOS[suite], vault_journey if suite == VAULT else aab_readback)
    finally:
        save()
        (connection.parent / "stop").touch()
    return 0 if scenarios.keys() == SUITE_SCENARIOS[suite] and all(row["status"] == "Passed" for row in scenarios.values()) else 1


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
