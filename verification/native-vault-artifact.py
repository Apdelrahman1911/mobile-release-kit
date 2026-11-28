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

VAULT_SUITES = {"vault-restart-stable", "vault-restart-unassigned", "vault-corruption", "vault-backup-restore"}
IOS_SUITES = VAULT_SUITES | {"artifact-ipa-direct"}
VERSION_FAULTS = {"version-substitution", "version-permissions", "version-storage", "webcontent-interruption", "version-keyboard"}
GIT_CHANGES = {"git-index", "git-commit", "git-stale-stage"}
SCENARIOS = {
    "vault-restart-stable": "vault-restart-reassess",
    "vault-restart-unassigned": "unassigned-vault-restart-reassess",
    "vault-corruption": "refuse-corrupt-owned-record",
    "vault-backup-restore": "encrypted-backup-and-independent-restored-revision",
    "artifact-synthetic": "artifact-picker-and-byte-inspection",
    "artifact-aab-direct": "direct-aab-structure-and-refusal",
    "artifact-aab-signed": "genuine-signed-aab-and-malformed-refusal",
    "artifact-ipa-direct": "direct-ipa-structure-and-refusal",
    "version-substitution": "refuse-replacing-the-reviewed-version-file",
    "version-permissions": "deny-version-save-with-read-only-project-folder",
    "version-storage": "version-save-on-bounded-full-apfs",
    "version-keyboard": "cancel-exact-version-confirmation-with-keyboard",
    "webcontent-interruption": "interrupt-only-owned-webcontent-during-version-review",
    "git-index": "git-index-review-stage-unstage",
    "git-commit": "git-local-review-cancel-and-commit",
    "git-stale-stage": "refuse-changed-reviewed-file-preserve-existing-index",
    "git-init": "never-adopt-existing-git-and-initialize-exact-empty-project",
    "installation-audit": "installation-read-only-correspondence",
    "github-malformed-target": "github-malformed-repository-refusal",
    "github-synthetic-denial": "invalid-session-token-denied-and-cleared",
}
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
    parent = work / "fault-volume" if suite == "version-storage" else work
    project = parent / ("MRK Verification iOS" if suite in IOS_SUITES else "MRK Verification Android")
    if suite == "version-storage":
        disk = plistlib.loads(call("/usr/sbin/diskutil", "info", "-plist", str(parent)).stdout)
        need(parent.is_mount() and parent.stat().st_dev != work.stat().st_dev
             and disk.get("FilesystemType") == "apfs" and disk.get("MountPoint") == str(parent)
             and 0 < disk.get("TotalSize", 0) <= 80 * 1024 * 1024, "only-bounded-disposable-apfs-volume")
    if suite in IOS_SUITES:
        fixture_file = Path("desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-persistence-v1.json")
        fixture = json.loads(fixture_file.read_bytes())
        for relative, encoded in fixture["files"].items():
            if relative.startswith("project/") or relative == "sources/synthetic.mobileprovision":
                target = project / relative.removeprefix("project/") if relative.startswith("project/") else work / relative
                need(target.resolve().is_relative_to(work.resolve()), "fixture-path-outside-work")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(base64.b64decode(encoded, validate=True))
        if suite == "artifact-ipa-direct":
            fixtures = importlib.util.spec_from_file_location("ios_artifact_helpers", Path("tests/unit/ios_artifact_helpers.py"))
            helper = importlib.util.module_from_spec(fixtures)
            fixtures.loader.exec_module(helper)
            ipa_root = work / "ipa-source"
            app = ipa_root / "Payload/Reader.app"
            app.mkdir(parents=True)
            (app / "Info.plist").write_bytes(plistlib.dumps(
                {"CFBundleIdentifier": "org.example.mrk.observed", "CFBundleExecutable": "Reader",
                 "CFBundleVersion": "7", "CFBundleShortVersionString": "1.2.3"}))
            (app / "Reader").write_bytes(helper.native_image(signature=None))
            helper.zip_tree(ipa_root, work / "synthetic.ipa")
            (work / "malformed.ipa").write_bytes(b"qualification fixture without any ZIP structure")
    else:
        shutil.copytree(FIXTURE, project)
        with zipfile.ZipFile(work / "synthetic.aab", "w") as archive:
            for name in ("BundleConfig.pb", "base/manifest/AndroidManifest.xml", "base/dex/classes.dex"):
                entry = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(entry, b"synthetic ZIP structure only; no DEX, manifest or signature")
        (work / "malformed.aab").write_bytes(b"qualification fixture without any ZIP structure")
    if suite != "git-init":
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
    parent = work / "fault-volume" if suite == "version-storage" else work
    project = parent / ("MRK Verification iOS" if suite in IOS_SUITES else "MRK Verification Android")
    def project_snapshot():
        leaves = {path.relative_to(project).as_posix(): file_hash(path) for path in project.rglob("*")
                  if path.is_file() and ".git" not in path.relative_to(project).parts}
        index = call("/usr/bin/git", "-C", str(project), "ls-files", "--stage", check=suite != "git-init").stdout
        head = call("/usr/bin/git", "-C", str(project), "rev-parse", "HEAD", check=suite != "git-init").stdout
        return leaves, index, head

    original_project = project_snapshot()
    original = {Path(name): digest for name, digest in original_project[0].items()}

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
        if suite in IOS_SUITES:
            # The real iOS identity is also shown in Apple setup. This is a
            # readback under the exact selected path, so identical labels are
            # allowed. No action targets either result.
            ui.node("Configured iOS bundle ID", category="statictext")
            ui.command("element.wait", selector={"text": "org.example.mrk.observed", "role": "statictext", "visible": True},
                       state="present", timeout_ms=10000)
        else:
            ui.node("org.mrk.fixture", contains=True)

        need(project_snapshot() == original_project, "project-originals")

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
            if suite != "vault-restart-stable":
                return state
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

        def backup_round_trip(known):
            backup, code = work / "backup-destination", work / "code-destination"
            backup.mkdir(mode=0o700)
            code.mkdir(mode=0o700)
            ui.click("Back up…", category="button", region=stored_profile)
            first_title = "Choose a folder for the encrypted signing backup"
            second_title = "Choose a different folder for the recovery code"
            ui.node(first_title, contains=True)
            ui.choose_path(backup, first_title)
            ui.node("Keep the recovery code separate from the encrypted backup.", contains=True)
            ui.choose_path(code, second_title)
            await_status("Backup saved")
            pair = []
            for folder in (backup, code):
                paths = list(folder.iterdir())
                need(len(paths) == 1, "backup-pair-roster")
                item = paths[0]
                info = item.lstat()
                need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                     and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 1024 * 1024, "backup-pair-private-custody")
                pair.append((item, file_hash(item)))
            need(profile_canary not in pair[0][0].read_bytes() and read_vault_state(with_profile=True) == known,
                 "backup-changed-originals-or-exposed-profile")
            facts["encryptedBackupAndSeparateCode"] = True
            save()
            ui.click("Restore a backup…", category="button", region="Encrypted backup and restore")
            for title, (item, _) in zip(("Choose your encrypted signing backup", "Choose the matching recovery code file"), pair, strict=True):
                ui.node(title, contains=True)
                ui.choose_path(item, title)
            await_status("Restore status")
            until(lambda: sum(row["visible"] and row["text"] == "Not assigned to the current draft" for row in
                                ui.command("tree.snapshot", limit=800)["nodes"]) == 2,
                  45, "restored-copy-not-observed-as-separate-unassigned-record")
            observed = read_vault_state(with_profile=2)
            need(observed[0] == known[0] and all(observed[1].get(key) == value for key,value in known[1].items()),
                 "restore-replaced-original-vault-record")
            need(all(file_hash(item) == expected for item,expected in pair)
                 and project_snapshot() == original_project,
                 "restore-mutated-backup-inputs-or-project")
            facts["restoreAddedNewUnassignedRecord"] = True

        if with_profile:
            source_hash = file_hash(profile_file)
            choose_option("Platform", "iOS", 1)
            choose_option("Release stage", "Candidate / internal testing", 0)
            choose_option("Input purpose", "Build / signing only", 1)
            initial = save_profile()
        if suite == "vault-backup-restore":
            backup_round_trip(initial)
            need(file_hash(profile_file) == source_hash, "original-profile-source-changed")
            return
        ui.click("Lock vault…", category="button")
        ui.click("Go back", category="button", region="Confirm private-input lock")
        await_status("Encrypted vault · unlocked")
        need(read_vault_state(with_profile=with_profile) == initial, "cancelled-lock-changed-vault")
        ui.click("Lock vault…", category="button")
        ui.click("Lock vault", category="button", region="Confirm private-input lock")
        await_status("Storage closed")
        need(read_vault_state(with_profile=with_profile) == initial, "lock-changed-vault-identity")
        facts["lockPreservedExactVault"] = True
        if suite in VAULT_SUITES:
            prior_pid = ui.payload_pid()
            ui.keys("command", "q")
            ui.node("Quit and discard unsaved drafts?", contains=True)
            ui.click("Quit", category="button")
            until(lambda: call("/usr/bin/pgrep", "-f", PAYLOAD_PATTERN, check=False).returncode == 1,
                  22, "predecessor-not-quit")
            need(read_vault_state(with_profile=True) == initial, "predecessor-quit-changed-vault")
            facts["normalQuitRetainedRecord"] = True
            save()
            if suite == "vault-corruption":
                need(os.environ.get("GITHUB_ACTIONS") == "true" and os.getuid() != 0
                     and Path.home() == Path("/Users/runner") and work.is_relative_to(Path(os.environ["RUNNER_TEMP"])),
                     "never-modify-nondisposable-credential-storage")
                original_folder, inventory = initial
                names = set(inventory) - controls.keys()
                need(len(names) == 1 and read_vault_state(with_profile=True) == initial,
                     "exact-single-synthetic-encrypted-record")
                name = names.pop()
                with os.fdopen(os.open(vault / name, os.O_RDWR | os.O_NOFOLLOW), "r+b") as stream:
                    metadata = os.fstat(stream.fileno())
                    need(metadata.st_ino == inventory[name][0] and metadata.st_uid == os.getuid()
                         and metadata.st_nlink == 1 and 248 <= metadata.st_size <= 65536,
                         "original-disposable-record-identity")
                    stream.seek(-1, os.SEEK_END)
                    original_byte = stream.read(1)
                    need(len(original_byte) == 1, "original-disposable-record-size")
                    stream.seek(-1, os.SEEK_END)
                    stream.write(bytes([original_byte[0] ^ 1]))
                    stream.flush()
                    os.fsync(stream.fileno())
                corrupted_state = read_vault_state(with_profile=True)
                need(corrupted_state[0] == original_folder
                     and all(corrupted_state[1][other] == identity for other, identity in inventory.items() if other != name)
                     and corrupted_state[1][name][0] == inventory[name][0]
                     and corrupted_state[1][name][1] != inventory[name][1], "other-vault-data-changed")
                facts["oneBitChangedInOnlyOwnedRecord"] = True
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
        if suite == "vault-corruption":
            def observe_corrupt_state():
                rows = [row for row in ui.command("tree.snapshot", limit=800)["nodes"] if row["visible"]]
                labels = {label for row in rows for label in (row["name"], row["text"])}
                need(not {"Assign this record to the submitted context?", "Assigned to current submitted context"} & labels,
                     "invalid-vault-record-exposed-assignment")
                if any(label in labels for label in ("asset_vault_corrupt", "vault-corrupt",
                       "The vault’s original files or authenticated data could not be validated. Keep them unchanged; the app will not repair, overwrite or silently skip them.")):
                    return "corrupt"
                if "Encrypted vault · unlocked" in labels:
                    return "unlocked"
                if "Encrypted vault · locked" in labels and any(row["name"] == "Unlock vault" and row["enabled"] for row in rows):
                    return "locked"
                return None

            outcome = until(observe_corrupt_state, 35, "corrupt-vault-open-outcome-absent")
            if outcome == "locked":
                ui.click("Unlock vault", category="button")
                outcome = until(lambda: (value if (value := observe_corrupt_state()) != "locked" else None),
                                35, "corrupt-vault-key-outcome-absent")
            if outcome == "unlocked":
                choose_option("Platform", "iOS", 1)
                choose_option("Release stage", "Candidate / internal testing", 0)
                choose_option("Input purpose", "Build / signing only", 1)
                await_status("Context submitted · not yet policy-validated")
                previous_digest = read_vault_state(with_profile=True)
                need(previous_digest == corrupted_state, "vault-open-repaired-corruption")
                ui.click("Assess and assign…", category="button", region=stored_profile)
                outcome = until(lambda: observe_corrupt_state() == "corrupt", 35, "corrupt-payload-not-rejected")
                facts["corruptionDetectedAtRecordAssessment"] = outcome is True
            else:
                facts["corruptionDetectedBeforeDecryption"] = outcome == "corrupt"
                need(outcome == "corrupt", "original-vault-did-not-report-corruption")
            need(read_vault_state(with_profile=True) == corrupted_state
                 and project_snapshot() == original_project,
                 "corruption-observation-changed-protected-files")
            facts["noRepairOrProjectMutationAndNoAssignment"] = True
            return
        await_status("Encrypted vault · locked")
        ui.click("Unlock vault", category="button")
        await_status("Encrypted vault · unlocked")
        need(read_vault_state(with_profile=with_profile) == initial and
             project_snapshot() == original_project,
             "reopen-changed-synthetic-vault-or-project")
        if with_profile:
            await_status("Not assigned to the current draft")
            ui.node("1", category="statictext", region="Private-input record revision")
            need(file_hash(profile_file) == source_hash, "original-profile-source-changed")
        facts["sameVaultReopenedAndUnlocked"] = True
        if suite in VAULT_SUITES:
            # Unlock must authenticate the existing encrypted record with
            # the preserved Keychain key. Inspect it without reassigning it.
            choose_option("Platform", "iOS", 1)
            choose_option("Release stage", "Candidate / internal testing", 0)
            choose_option("Input purpose", "Build / signing only", 1)
            await_status("Context submitted · not yet policy-validated")
            if suite in VAULT_SUITES:
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
            markers = {"assessment_context_stale", "AssetStatusInvalid", "asset_cleanup_unknown",
                       "This original session is no longer usable. Check its cleanup status; do not start another operation."}
            nodes = [row for row in ui.command("tree.snapshot", limit=800)["nodes"] if row["visible"]]
            parents = [row["id"] + "." for row in nodes if row["name"] == "Explicit private-input review"]
            labels = {label for row in nodes for label in (row["name"], row["text"])}
            discardable = len(parents) == 1 and any(row["id"].startswith(parents[0]) and row["role"] == "button"
                and row["name"] == "Discard review" and row["enabled"] for row in nodes)
            facts["reassessmentReviewWasDiscardable"] = discardable
            facts["reassessmentRefusalMarkers"] = sorted(labels & markers)
            facts["unchangedAtReassessment"] = read_vault_state(with_profile=True) == initial
            save()
            need(facts["unchangedAtReassessment"], "assessment-changed-original-before-decision")
            need(discardable, "original-reassessment-discard-unavailable")
            ui.click("Discard review", category="button", region="Explicit private-input review")
            await_status("Not assigned to the current draft")
            need(read_vault_state(with_profile=True) == initial, "assessment-changed-original-encrypted-record")
            need(project_snapshot() == original_project and file_hash(profile_file) == source_hash,
                 "assessment-changed-project-or-selected-profile")
            facts["originalRecordDecryptedForEnvelopeAssessmentAndKeptUnassigned"] = True

    def aab_readback():
        ui.page("Build files")
        consent = "Confirm selected artifact inspection"
        report = "Artifact byte inspection result"
        ipa = suite == "artifact-ipa-direct"
        suffix = "ipa" if ipa else "aab"
        picker = "Choose " + suffix.upper()
        title = "Choose an iOS IPA to inspect" if ipa else "Choose an Android App Bundle to inspect"
        if ipa:
            ui.click("Artifact format", category="popupbutton")
            ui.keys("home")
            ui.keys("down")
            ui.keys("return")
            ui.node(picker, category="button")
        facts = results["artifactInspection"] = {}

        def inspect(path):
            input_digest = file_hash(path)
            ui.click(picker, category="button")
            ui.node(title, contains=True)
            entry = facts.setdefault("nativeArtifactReads", {}).setdefault(path.name, {})
            entry["panelOpened"] = True
            save()
            ui.choose_path(path, title)
            entry["nativeChooserReturned"] = True
            save()
            ui.node(path.name, category="statictext", contains=True)
            entry["selectedNameVisible"] = True
            save()
            ui.click("Review artifact inspection", category="button")
            ui.node("Inspect these selected inputs?", category="heading")
            _, start = ui.node("Inspect selected bytes", category="button", region=consent)
            need(not start["enabled"], "artifact-inspection-enabled-without-consent")
            ui.click("I understand this inspects only the selected bytes", category="checkbox", contains=True, region=consent)
            ui.click("Inspect selected bytes", category="button", region=consent)
            entry["requestedOneInspectedReadAfterConsent"] = True
            save()
            until(lambda: any(row["visible"] and row["name"] == "Recorded artifact checks" for row in
                  ui.command("tree.snapshot", limit=800)["nodes"]), 55, "original-artifact-check-report-unavailable")
            ui.node(input_digest, category="statictext", contains=True, region=report)
            need(file_hash(path) == input_digest and
                 project_snapshot() == original_project,
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

        if suite == "artifact-synthetic":
            ui.click(picker, category="button")
            ui.node(title, contains=True)
            ui.click("Cancel", category="button")
            _, review = ui.node("Review artifact inspection", category="button")
            need(not review["enabled"], "cancelled-artifact-picker-retained-inspection-input")
            facts["pickerCancelLeftNoInput"] = True
            save()

            def ready_to_choose():
                rows = ui.command("tree.snapshot", limit=600)["nodes"]
                buttons = [row for row in rows if row["visible"] and row["name"] == picker and row["role"]=="button"]
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
        genuine = suite == "artifact-aab-signed"
        selected = work / ("signed-synthetic.aab" if genuine else "synthetic." + suffix)
        rows = inspect(selected)
        facts["syntheticStructureChecks"] = rows
        save()
        need(rows["Observed byte identity"] == "Passed this check" and
             rows["Package or archive structure"] == "Passed this check", "original-artifact-byte-or-structure-check")
        if genuine:
            facts["genuineSignedAabInspected"] = True
            facts["nativeSignatureObservation"] = rows["Cryptographic signature"]
            need(rows["Cryptographic signature"] != "Failed this check", "genuine-aab-native-signature-refused")
        else:
            need(rows["Cryptographic signature"] != "Passed this check", "unsigned-structure-gained-signature-credit")
        facts["syntheticStructureInspected"] = True
        save()
        ui.click("Discard selection and review", category="button")
        _, review = ui.node("Review artifact inspection", category="button")
        need(not review["enabled"], "discard-retained-original-review")
        rows = inspect(work / ("malformed." + suffix))
        facts["malformedArchiveChecks"] = rows
        save()
        need(rows["Package or archive structure"] == "Failed this check" and
             rows["Cryptographic signature"] != "Passed this check", "malformed-archive-not-reported-as-failed")
        facts["malformedArchiveRejectedWithoutChangingInputs"] = True

    def focus_probe(action, key):
        # This helper never reads input content. It matches a fixed control
        # label in one exact frontmost window and confirms focus identity.
        probe = work / "fixture-focus"
        if not probe.is_file():
            swift = work / "fixture-focus.swift"
            swift.write_text("""
import AppKit
import ApplicationServices

func get(_ element: AXUIElement, _ key: String) -> CFTypeRef? {
    var data: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, key as CFString, &data) == .success ? data : nil
}

func matches(_ element: AXUIElement, role: String, label: String) -> Bool {
    guard get(element, kAXRoleAttribute) as? String == role else { return false }
    if [kAXTitleAttribute, kAXDescriptionAttribute].contains(where: { get(element, $0) as? String == label }) {
        return true
    }
    guard let title = get(element, kAXTitleUIElementAttribute), CFGetTypeID(title) == AXUIElementGetTypeID() else {
        return false
    }
    let text = unsafeDowncast(title, to: AXUIElement.self)
    return [kAXTitleAttribute, kAXValueAttribute, kAXDescriptionAttribute].contains { get(text, $0) as? String == label }
}

let args = CommandLine.arguments
guard args.count == 4, let pid = Int32(args[1]), pid > 0, AXIsProcessTrusted(),
      NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else { exit(2) }
let app = AXUIElementCreateApplication(pid)
guard AXUIElementSetMessagingTimeout(app, 1) == .success,
      let windows = get(app, kAXWindowsAttribute) as? [AXUIElement], windows.count == 1,
      get(windows[0], kAXTitleAttribute) as? String == "Mobile Release Kit" else { exit(3) }
let action = args[2], label = args[3]
if action == "read", label == "Keep reviewing" {
    if let focus = get(app, kAXFocusedUIElementAttribute), CFGetTypeID(focus) == AXUIElementGetTypeID() {
        let element = unsafeDowncast(focus, to: AXUIElement.self)
        print(matches(element, role: "AXButton", label: label) ? "focused" : "other")
    } else { print("other") }
} else if action == "focus", ["Author name", "Author email"].contains(label) {
    var queue = [windows[0]], hits: [AXUIElement] = [], visited = 0
    while let element = queue.popLast() {
        visited += 1
        guard visited + queue.count <= 4096 else { exit(4) }
        if matches(element, role: "AXTextField", label: label) { hits.append(element) }
        queue.append(contentsOf: get(element, kAXChildrenAttribute) as? [AXUIElement] ?? [])
    }
    guard hits.count == 1,
          (get(hits[0], kAXEnabledAttribute) as? NSNumber)?.boolValue == true,
          NSWorkspace.shared.frontmostApplication?.processIdentifier == pid,
          AXUIElementSetAttributeValue(hits[0], kAXFocusedAttribute as CFString, kCFBooleanTrue) == .success,
          let focus = get(app, kAXFocusedUIElementAttribute),
          CFEqual(focus, hits[0]) else { exit(5) }
    print("focused")
} else { exit(6) }
""")
            call("/usr/bin/xcrun", "swiftc", str(swift), "-o", str(probe), timeout=45)
        reply = call(str(probe), str(ui.payload_pid()), action, key, check=False, timeout=8)
        need(reply.returncode == 0 and reply.stdout in {b"focused\n", b"other\n"},
             "exact-fixture-focus-probe-" + str(reply.returncode))
        return reply.stdout == b"focused\n"

    def version_fault_journey():
        nonlocal connection
        target = project / VERSION_FILE
        owner = target.parent
        owned = owner.lstat()
        need(owned.st_uid == os.getuid() != 0 and owner.is_relative_to(work)
             and not owner.is_symlink(), "only-owned-disposable-fixture-directory")
        expected = "Values: 1.0.0 · Build 1."
        initial_files = {path.relative_to(project): (file_hash(path), path.stat().st_ino)
                         for path in project.rglob("*") if path.is_file()
                         and ".git" not in path.relative_to(project).parts}
        need(set(initial_files) == set(original), "exact-original-project-inventory")
        fact = results["versionFault"] = {"mode": suite}

        def originals_preserved():
            observed = {path.relative_to(project): (file_hash(path), path.stat().st_ino)
                        for path in project.rglob("*") if path.is_file()
                        and ".git" not in path.relative_to(project).parts}
            need(observed == initial_files, "version-fault-changed-project-identity-or-bytes")
            fact["originalFileInventoryDigestsAndInodesPreserved"] = True
            save()

        ui.page("Overview")
        ui.click("Edit version & build number")
        ui.click("Open saved version editor", category="button")
        ui.node(expected, category="statictext", contains=True)
        ui.edit("Marketing version", "1.1.5")
        ui.edit("Build number", "7")
        ui.click("Validate and review values", category="button")
        ui.node("Edit only the two selected value spans", category="heading", contains=True)
        ui.click("Save version values…", category="button")
        ui.node("Save the new version?", category="heading", contains=True)
        _, submit = ui.node("Save version values", category="button")
        need(not submit["enabled"], "apply-active-without-approval")
        fact["explicitReviewInitiallyRequired"] = True
        if suite == "version-keyboard":
            def returned_to_review():
                tree = ui.command("tree.snapshot", limit=800)
                nodes = [node for node in tree["nodes"] if node["visible"]]
                if any(node["name"] == "Save the new version?" and node["role"] == "heading" for node in nodes):
                    return False
                # Native snapshot size is bounded. Require affirmative readback
                # of the main review, rather than inferring absence from a
                # truncated accessibility tree.
                return any(node["name"] == "Save version values…" and node["enabled"] and node["role"] == "button"
                           for node in nodes)
            ui.keys("escape")
            until(returned_to_review, 10, "escape-did-not-return-to-original-review")
            originals_preserved()
            fact["escapeReturnedToReview"] = True
            save()
            ui.click("Save version values…", category="button")
            ui.node("Save the new version?", category="heading", contains=True)
            ui.keys("return")
            originals_preserved()
            if not returned_to_review():
                for _ in range(12):
                    if focus_probe("read", "Keep reviewing"):
                        break
                    ui.keys("tab")
                else:
                    raise AssertionError("cancel-control-not-reachable-through-native-tab-cycle")
                ui.keys("space")
                until(returned_to_review, 10, "keyboard-focused-cancel-did-not-return-to-review")
                originals_preserved()
                fact["tabLocatedOriginalCancelAndSpaceActivatedIt"] = True
            else:
                fact["returnDismissedOriginalModalWithoutSaving"] = True
            return

        ui.click("I reviewed the change.", category="checkbox")
        ui.node("Save version values", category="button", enabled=True)
        if suite == "version-storage":
            mounted = work / "fault-volume"
            need(mounted.is_mount() and owner.stat().st_dev == mounted.stat().st_dev != work.stat().st_dev
                 and owner.stat().st_uid == os.getuid() != 0, "only-isolated-apfs-fixture")
            filler = mounted / "synthetic-capacity-fixture.bin"
            failed = False
            try:
                with filler.open("xb", buffering=0) as output:
                    # The backing image is capped at 64 MiB. An upper bound
                    # independent of reported free space protects the runner.
                    for size, max_writes in ((1024 * 1024, 80), (4096, 1024)):
                        wrote_all = True
                        for _ in range(max_writes):
                            try:
                                if output.write(os.urandom(size)) != size:
                                    wrote_all = False
                                    break
                            except OSError as error:
                                if error.errno != errno.ENOSPC:
                                    raise
                                wrote_all = False
                                if size == 4096:
                                    failed = True
                                break
                        need(not wrote_all, "apfs-fixture-never-reached-capacity")
                need(failed, "apfs-fixture-did-not-return-enospc")
                fact["isolatedVolumeReturnedENOSPC"] = True
                save()
                ui.click("Save version values", category="button")
                needles = {"Version operation settled — no success assumed", "Version outcome or cleanup is unverified",
                           "Submitted version values saved", "This review is no longer eligible."}
                seen = until(lambda: {label for node in ui.command("tree.snapshot", limit=800)["nodes"] if node["visible"]
                                      for label in (node["name"], node["text"]) if label in needles},
                             55, "no-visible-result-from-original-no-space-save")
                fact["observedOriginalOutcome"] = sorted(seen)
                originals_preserved()
                need(seen == {"Version operation settled — no success assumed"}, "no-proven-final-no-space-denial")
            finally:
                if filler.is_file() and not filler.is_symlink():
                    filler.unlink()
            need(os.statvfs(mounted).f_bavail > 0, "apfs-fixture-did-not-reclaim-capacity")
            fact["reclaimedDisposableVolumeCapacity"] = True
            return
        if suite == "version-substitution":
            need(os.environ.get("GITHUB_ACTIONS")=="true" and owner.stat().st_uid==os.getuid()!=0
                 and not target.is_symlink() and (target.stat().st_nlink==1),
                 "only-owned-disposable-file-is-replaceable")
            backup = work / "retained-original-version.properties"
            foreign = work / "untouched-alternate-project-version.properties"
            original_inode = target.stat().st_ino
            original_body = target.read_bytes()
            foreign_body = b"VERSION_NAME=99.8.7\nBUILD_NUMBER=123456\n"
            with foreign.open("xb") as file:
                file.write(foreign_body)
            foreign_inode = foreign.stat().st_ino
            need(not backup.exists() and target.is_relative_to(project), "unexpected-test-custody")
            target.rename(backup)
            target.symlink_to(foreign)
            need(target.is_symlink() and target.resolve()==foreign and backup.stat().st_ino==original_inode,
                 "actual-version-source-substitution-missing")
            fact["ownedFixtureReplacedAfterExplicitReview"] = True
            save()
            _, control = ui.node("Save version values",category="button")
            if control["enabled"]:
                ui.click("Save version values",category="button")
                fact["sentOneOriginalReviewedApply"] = True
            status = {"Version operation settled — no success assumed", "Version outcome or cleanup is unverified",
                      "Submitted version values saved", "This review is no longer eligible."}
            seen = until(lambda: {label for node in ui.command("tree.snapshot", limit=800)["nodes"] if node["visible"]
                                  for label in (node["name"], node["text"]) if label in status or label.startswith("This review is no longer eligible.")},
                         55,"no-original-outcome-for-substituted-version-input")
            fact["observedOriginalOutcome"] = sorted(seen)
            save()
            need("Submitted version values saved" not in seen and
                 ("Version operation settled — no success assumed" in seen or
                   any(label.startswith("This review is no longer eligible.") for label in seen)),
                 "substituted-file-has-no-confirmed-refusal")
            need(target.is_symlink() and target.readlink()==foreign and foreign.read_bytes()==foreign_body
                 and foreign.stat().st_ino==foreign_inode and backup.read_bytes()==original_body
                 and backup.stat().st_ino==original_inode, "refusal-altered-foreign-source-or-held-original")
            need(all(file_hash(project/path)==digest for path,digest in original.items() if path!=VERSION_FILE),
                 "refusal-altered-unrelated-project-file")
            fact["heldOriginalAndUnrelatedSymlinkTargetPreserved"] = True
            return
        if suite == "version-storage":
            mounted = work / "fault-volume"
            need(mounted.is_mount() and owner.stat().st_dev == mounted.stat().st_dev != work.stat().st_dev
                 and owner.stat().st_uid == os.getuid() != 0, "only-isolated-apfs-fixture")
            filler = mounted / "synthetic-capacity-fixture.bin"
            failed = False
            tail = mounted / "synthetic-small-file-capacity"
            tail.mkdir(mode=0o700)
            try:
                with filler.open("xb", buffering=0) as output:
                    # The backing image is capped at 64 MiB. An upper bound
                    # independent of reported free space protects the runner.
                    for size, max_writes in ((1024 * 1024, 80), (4096, 1024)):
                        wrote_all = True
                        for _ in range(max_writes):
                            try:
                                if output.write(os.urandom(size)) != size:
                                    wrote_all = False
                                    break
                            except OSError as error:
                                if error.errno != errno.ENOSPC:
                                    raise
                                wrote_all = False
                                if size == 4096:
                                    failed = True
                                break
                        need(not wrote_all, "apfs-fixture-never-reached-capacity")
                need(failed, "apfs-fixture-did-not-return-enospc")
                fact["isolatedVolumeReturnedENOSPC"] = True
                small_write_denied = False
                chunk = b"owned test capacity\n" * 205
                for index in range(2048):
                    probe = tail / str(index)
                    try:
                        with probe.open("xb", buffering=0) as output:
                            written = output.write(chunk)
                            os.fsync(output.fileno())
                        if written != len(chunk):
                            break
                    except OSError as error:
                        if error.errno != errno.ENOSPC:
                            raise
                        small_write_denied = True
                        break
                fact["smallFixtureWriteReturnedEnospc"] = small_write_denied
                capacity = os.statvfs(mounted)
                fact["availableBytesWhenSubmitting"] = capacity.f_bavail * capacity.f_frsize
                save()
                ui.click("Save version values", category="button")
                needles = {"Version operation settled — no success assumed", "Version outcome or cleanup is unverified",
                           "Submitted version values saved", "This review is no longer eligible."}
                seen = until(lambda: {label for node in ui.command("tree.snapshot", limit=800)["nodes"] if node["visible"]
                                      for label in (node["name"], node["text"]) if label in needles},
                             55, "no-visible-result-from-original-no-space-save")
                fact["observedOriginalOutcome"] = sorted(seen)
                expected_bytes = b"VERSION_NAME=1.1.5\nBUILD_NUMBER=7\n"
                current = target.read_bytes()
                fact["observedVersionSha256"] = hashlib.sha256(current).hexdigest()
                fact["originalBytes"] = current == (b"VERSION_NAME=1.0.0\nBUILD_NUMBER=1\n")
                fact["onlyReviewedBytes"] = current == expected_bytes
                save()
                if seen == {"Submitted version values saved"}:
                    affected = target.relative_to(project)
                    observed = {path.relative_to(project): (file_hash(path), path.stat().st_ino)
                                for path in project.rglob("*") if path.is_file()
                                and ".git" not in path.relative_to(project).parts}
                    need(fact["onlyReviewedBytes"] and set(observed) == set(initial_files)
                         and all(observed[path] == identity for path, identity in initial_files.items() if path != affected),
                         "success-did-not-match-exact-approved-bytes-and-unrelated-originals")
                    fact["approvedSmallSaveCompletedWithinAvailableSpace"] = True
                else:
                    originals_preserved()
                    need(seen == {"Version operation settled — no success assumed"}, "no-proven-final-no-space-denial")
                    fact["originalWriteRefusalAndCleanupConfirmed"] = True
            finally:
                if filler.is_file() and not filler.is_symlink():
                    filler.unlink()
                tail = mounted / "synthetic-small-file-capacity"
                if tail.is_dir() and not tail.is_symlink():
                    shutil.rmtree(tail)
            need(os.statvfs(mounted).f_bavail > 0, "apfs-fixture-did-not-reclaim-capacity")
            fact["reclaimedDisposableVolumeCapacity"] = True
            return
        if suite == "version-permissions":
            mode = stat.S_IMODE(owned.st_mode)
            try:
                owner.chmod(mode & ~0o222)
                probe = owner / "mrk-permission-check-synthetic"
                try:
                    probe.touch(exist_ok=False)
                except PermissionError:
                    fact["osDeniedCreationInDirectory"] = True
                else:
                    probe.unlink()
                    raise AssertionError("permission-fixture-does-not-deny")
                ui.click("Save version values", category="button")
                needles = {"Version operation settled — no success assumed", "Version outcome or cleanup is unverified",
                           "Submitted version values saved", "This review is no longer eligible."}
                status = until(lambda: {label for node in ui.command("tree.snapshot", limit=800)["nodes"] if node["visible"]
                                        for label in (node["name"], node["text"]) if label in needles},
                               55, "no-visible-result-from-original-denied-save")
                fact["observedOriginalOutcome"] = sorted(status)
                originals_preserved()
                need(status == {"Version operation settled — no success assumed"}, "no-proven-final-denial")
            finally:
                owner.chmod(mode)
            need(stat.S_IMODE(owner.stat().st_mode) == mode and os.access(owner, os.W_OK),
                 "restored-only-disposable-fixture-directory")
            fact["fixturePermissionsRestored"] = True
            return

        if suite == "webcontent-interruption":
            payload_pid = ui.payload_pid()
            identity = re.compile(r"^/System/Library/Frameworks/WebKit\.framework/Versions/[A-Za-z]+/XPCServices/"
                                  r"com\.apple\.WebKit\.WebContent(\.EnhancedSecurity)?\.xpc/Contents/MacOS/"
                                  r"com\.apple\.WebKit\.WebContent(\.EnhancedSecurity)?$")
            def original_worker():
                observed = call("/bin/ps", "-A", "-o", "pid=", "-o", "ppid=", "-o", "uid=", "-o", "comm=").stdout.decode()
                owned = []
                selected = 0
                for row in observed.splitlines():
                    columns = row.strip().split(None, 3)
                    if len(columns) != 4:
                        continue
                    pid, parent, uid, path = columns
                    if int(uid) != os.getuid() or not identity.fullmatch(path):
                        continue
                    selected += 1
                    responsible = int(parent) == payload_pid
                    if not responsible:
                        lookup = call("/usr/bin/sudo", "-n", "/bin/launchctl", "procinfo", pid, timeout=5, check=False)
                        if lookup.returncode == 0:
                            pointers = re.findall(r"(?im)^\s*responsible\s+(?:process\s+)?pid\s*[:=]\s*([0-9]+)\b",
                                                  lookup.stdout.decode(errors="replace"))
                            responsible = pointers == [str(payload_pid)]
                    if responsible:
                        owned.append(int(pid))
                return selected, owned
            need(os.environ.get("GITHUB_ACTIONS") == "true" and os.getuid() != 0
                 and Path.home() == Path("/Users/runner") and work.is_relative_to(Path(os.environ["RUNNER_TEMP"])), "no-signal-on-user-host")
            selected, owned = original_worker()
            fact["webkitCandidates"] = selected
            fact["responsiblePidMatches"] = len(owned)
            save()
            if len(owned) != 1:
                raise Blocked("Runner metadata did not bind exactly one Apple WebContent process to the installed app PID")
            worker, = owned
            need(worker > 1 and worker != payload_pid and original_worker()[1] == [worker],
                 "webkit-process-binding-changed-before-interruption")
            call("/bin/kill", "-KILL", str(worker))
            until(lambda: call("/bin/ps", "-p", str(worker), "-o", "pid=", check=False).returncode == 1,
                  12, "bound-webcontent-did-not-exit")
            need(ui.payload_pid() == payload_pid, "signed-payload-exited-while-only-webcontent-was-interrupted")
            fact["onlyRecognizedWebContentExited"] = True
            originals_preserved()
            # A fresh document may intentionally refuse to reattach the old
            # native session. A blank view is never reported as recovery.
            def observed_recovery():
                nodes = ui.command("tree.snapshot", limit=800)["nodes"]
                headings = {node["name"] for node in nodes if node["visible"] and node["role"] == "heading"}
                if "Save the new version?" in headings:
                    raise AssertionError("old-unsubmitted-review-survived-webcontent-loss")
                return any(node["name"] == "Overview" and node["role"] == "button" and node["enabled"] for node in nodes)
            # Document loss permanently invalidates the old native binding.
            # Inspect that distinct state, then use the app’s native Quit menu
            # and a new ordinary launch to test supported recovery end to end.
            fact["oldReviewGoneWithoutAutomaticRecovery"] = not observed_recovery()
            ui.snapshot("after-webcontent-loss")
            access = call(str(CLI),"status","--json",check=False)
            need(access.returncode in {3,4},"lost-document-still-reported-cli-authority")
            fact["oldDocumentNoCliAuthority"] = True
            save()
            close_source=work / "original-window-close.swift"
            close_source.write_text('''
import AppKit
import ApplicationServices
import Foundation
guard CommandLine.arguments.count == 2,
      let pid = Int32(CommandLine.arguments[1]), pid > 1,
      AXIsProcessTrusted(),
      NSWorkspace.shared.frontmostApplication?.processIdentifier == pid
else { exit(2) }
let app = AXUIElementCreateApplication(pid)
var windowValue: AnyObject?
guard AXUIElementCopyAttributeValue(app, kAXFocusedWindowAttribute as CFString, &windowValue) == .success,
      let windowValue, CFGetTypeID(windowValue) == AXUIElementGetTypeID()
else { exit(3) }
let window = unsafeBitCast(windowValue, to: AXUIElement.self)
var title: AnyObject?
var controlValue: AnyObject?
guard AXUIElementCopyAttributeValue(window, kAXTitleAttribute as CFString, &title) == .success,
      title as? String == "Mobile Release Kit",
      AXUIElementCopyAttributeValue(window, kAXCloseButtonAttribute as CFString, &controlValue) == .success,
      let controlValue, CFGetTypeID(controlValue) == AXUIElementGetTypeID()
else { exit(4) }
let control = unsafeBitCast(controlValue, to: AXUIElement.self)
guard AXUIElementPerformAction(control, kAXPressAction as CFString) == .success else { exit(5) }
print("original-native-close-sent")
''')
            result=call("/usr/bin/xcrun","swift",str(close_source),str(payload_pid),timeout=30,check=False)
            fact["nativeWindowCloseStatus"]=result.returncode
            need(result.returncode==0 and result.stdout==b"original-native-close-sent\n",
                 "original-native-window-close-not-sent")
            save()
            try:
                ui.node("Quit and discard unsaved drafts?",contains=True)
            except Exception as error:
                if getattr(error,"status",None)!=408:
                    raise
                fact["nativeConfirmationAbsentAfterWindowClose"] = True
                originals_preserved()
                # Pre-submit only, so this forced recovery cannot be mistaken
                # for settlement of an accepted write or original native Quit.
                need(ui.payload_pid()==payload_pid,"old-payload-changed-before-recovery")
                call("/bin/kill","-KILL",str(payload_pid))
            else:
                ui.click("Quit",category="button")
                fact["nativeConfirmationAcceptedAfterWindowClose"] = True
                save()
            prior_pid=payload_pid
        else:
            prior_pid = ui.payload_pid()
            original_process = call("/bin/ps", "-p", str(prior_pid), "-o", "uid=", "-o", "command=").stdout
            uid, executable = original_process.decode().strip().split(None, 1)
            need(int(uid) == os.getuid() and re.search(PAYLOAD_PATTERN, executable) is not None,
                 "refuse-signal-to-nonfixture-process")
            fact["killedExactPidBeforeSubmit"] = prior_pid
            save()
            call("/bin/kill", "-KILL", str(prior_pid))
        until(lambda: call("/bin/ps", "-p", str(prior_pid), "-o", "pid=", check=False).returncode == 1,
              15, "original-payload-did-not-exit")
        originals_preserved()
        call("/usr/bin/open", "-a", str(APP))
        reopened_pid = until(lambda: ui.reopened_payload_pid(prior_pid), 18, "new-payload-did-not-launch")
        previous = {str(path) for path in Path(os.environ["RUNNER_TEMP"]).glob("ui-session-*/connection.json")}
        token = secrets.token_hex(32)
        (work / "reopen-token").write_text(token + "\n")
        request = work / "reopen-request.next"
        request.write_text(hashlib.sha256(token.encode("ascii")).hexdigest() + "\n")
        request.replace(work / "reopen-token-digest")
        (connection.parent / "stop").touch()
        connection, ui.client = open_session(work, action, previous=previous, token_name="reopen-token")
        need(ui.payload_pid() == reopened_pid, "reopened-payload-identity-changed")
        fact["reopenedExactCandidateNewPid"] = reopened_pid
        ui.click("Overview", category="button")
        empty = PAGE_HEADINGS["Overview"]
        def reopened_overview():
            allowed = {empty, project.name}
            seen = {node["name"] for node in ui.command("tree.snapshot", limit=300)["nodes"]
                    if node["role"] == "heading" and node["visible"] and node["name"] in allowed}
            need(len(seen) <= 1, "ambiguous-restarted-overview")
            return next(iter(seen)) if seen else None
        if until(reopened_overview, 20, "no-reopened-overview") == empty:
            ui.project_name = None
            ui.pick(project)
        else:
            ui.project_name = project.name
        ui.click("Edit version & build number")
        ui.click("Open saved version editor", category="button")
        ui.node(expected, category="statictext", contains=True)
        nodes = ui.command("tree.snapshot", limit=800)["nodes"]
        need(not any(node["visible"] and node["name"] in
                     {"Save the new version?", "I reviewed the change.", "Save version values…", "Save version values"}
                     for node in nodes), "stale-approval-or-draft-replayed")
        originals_preserved()
        fact["staleReviewAbsentOriginalValuesReadback"] = True

    def git_nodes(region, name, role, *, enabled=False):
        tree = ui.command("tree.snapshot", limit=800)
        containers = [row for row in tree["nodes"] if row["role"] == "group" and row["name"] == region and row["visible"]]
        need(len(containers) <= 1, "ambiguous-git-original-region-" + region)
        if not containers:
            return []
        prefix = containers[0]["id"] + "."
        return [row for row in tree["nodes"] if row["id"].startswith(prefix) and row["role"] == role
                and row["visible"] and name in (row["name"], row["text"]) and (not enabled or row["enabled"])]

    def git_has(name, role, region, *, enabled=False):
        return len(git_nodes(region, name, role, enabled=enabled)) == 1

    def wait_for_git_original(title, region, *, read=False, outcome=None):
        status = "Local Git read status" if read else "Local Git action status"
        check = "Check read" if read else "Check action"
        refused = ("Local Git read did not complete", "Local Git read needs attention") if read else (
            "Git action did not complete", "Git action needs attention", "Git recovery is needed")
        next_check = time.monotonic() + 3

        def observe():
            nonlocal next_check
            if git_has(title, "heading", region) and (outcome is None or outcome()):
                return True
            if any(git_has(label, "heading", status) for label in refused):
                raise AssertionError("original-git-operation-refused-" + title)
            if not read and time.monotonic() >= next_check and git_has(check, "button", status, enabled=True):
                ui.click(check, category="button", region=status)
                next_check = time.monotonic() + 4
            return False

        until(observe, 60, "original-git-result-" + title)

    def git_initialize():
        ui.page("GitHub")
        ui.click("Connect", category="radiobutton", region="GitHub tasks")
        scope = "Set up local Git"
        preview = "Review local Git initialization"
        review = "Review Git setup"
        apply = "Create local repository"
        fact = results["gitInitialize"] = {}
        need(not os.path.lexists(project / ".git") and project.is_relative_to(work), "disposable-project-not-empty-of-git")
        status = "Local Git action status"

        def ready_for_review():
            ui.click("Check local Git actions", category="button", region=status)
            until(lambda: git_has(review, "button", scope, enabled=True), 10, "initialize-review-admission")

        def begin_review():
            ui.click(review, category="button", region=scope)
            wait_for_git_original("Create an empty local repository", preview, read=False)
            _, button = ui.node(apply, category="button", region=preview)
            need(not button["enabled"], "unreviewed-initialization-admitted")

        ready_for_review()
        begin_review()
        ui.click("Close review, keep draft", category="button", region=status)
        need(not os.path.lexists(project / ".git"), "cancel-created-git-owner")
        fact["cancelPreservedNoGitMetadata"] = True
        save()
        ready_for_review()
        begin_review()
        ui.click("I reviewed this folder. Create only its empty local Git repository.",
                 category="checkbox", region=preview)
        ui.click(apply, category="button", region=preview)
        wait_for_git_original("Local repository created", status, read=False)
        def git(*args, check=True):
            return call("/usr/bin/git","-C",str(project),*args,check=check)
        folder = project / ".git"
        need(folder.is_dir() and not folder.is_symlink() and folder.stat().st_uid==os.getuid()
             and git("symbolic-ref","HEAD").stdout.startswith(b"refs/heads/")
             and git("rev-parse","--verify","HEAD",check=False).returncode!=0
             and git("remote").stdout==b"" and git("ls-files").stdout==b"",
             "git-init-unexpected-remote-commit-or-index")
        expected={path.relative_to(project):file_hash(path) for path in project.rglob("*")
                  if path.is_file() and ".git" not in path.relative_to(project).parts}
        need(expected==original,"local-git-initialization-changed-project-bytes")
        fact["emptyOwnedRepositoryCreatedWithoutSourceChanges"] = True

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
                checked = call("/usr/bin/swift", "verification/git-review-focus.swift", "git-review",
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
                rows = json.loads(call("/usr/bin/swift", "verification/git-review-focus.swift", str(frame), timeout=20).stdout)
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
                rows = json.loads(call("/usr/bin/swift", "verification/git-review-focus.swift", str(frame), timeout=20).stdout)
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
                    if suite == "git-commit" and name == "Review the complete staged commit" and tree["truncated"]:
                        if native_control(review, "AXHeading", name)["matches"] == 1:
                            fact["completeCommitReviewFoundInsideOriginalRegion"] = True
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
                            # Preparing and applying both own native requests.
                            # Their original status can lie outside the capped tree.
                            check = native_control(status_region, "AXButton", "Check action")
                            if check["matches"] == 1 and check.get("enabled") is True:
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

            press_after_settlement(status_region, "Check local Git actions")
            if suite == "git-commit":
                observation = results["gitCommit"] = {}
                changes = "Local Git changes"
                start = "Review complete commit"
                title = "Review the complete staged commit"
                apply = "Create this local commit"
                message = "Verify one reviewed local commit"
                author = "MRK Synthetic Author"
                email = "fixture@example.invalid"
                ui.click("Create a local commit", contains=True)
                _, review_button = ui.node(start, category="button")
                need(not review_button["enabled"], "empty-commit-admitted")
                verify_change(True)
                observation["incompleteDraftKeptOriginalStagedIndex"] = True
                ui.click("Commit message", category="textarea")
                ui.command("text.insert", text=message)
                def edit_author(label, value):
                    need(focus_probe("focus", label), "author-field-not-focused")
                    ui.keys("command", "a")
                    ui.command("text.insert", text=value)
                edit_author("Author name", author)
                edit_author("Author email", "not-an-email")
                _, review_button = ui.node(start, category="button")
                need(not review_button["enabled"], "malformed-email-admitted")
                verify_change(True)
                observation["malformedEmailKeptOriginalStagedIndex"] = True
                edit_author("Author email", email)
                press_after_settlement(changes, start)
                await_heading(title)
                values = (message, author, email, "README.md")
                need(all(native_control(review, "AXStaticText", value)["matches"] == 1 for value in values),
                     "commit-author-message-or-roster-not-readback")
                control = native_control(review, "AXButton", apply)
                need(control["matches"] == 1 and control["enabled"] is False, "commit-enabled-without-review-checkbox")
                native_control(status_region, "AXButton", "Close review, keep draft", press=True)
                verify_change(True)
                observation["cancelPreservedStagedBytesAndHead"] = True
                save()
                press_after_settlement(changes, start)
                await_heading(title)
                need(native_control(review, "AXStaticText", "README.md")["matches"] == 1, "commit-review-path")
                need(native_control(review, "AXCheckBox", reviewed).get("checked") is False, "commit-consent-starts-clear")
                native_control(review, "AXCheckBox", reviewed, press=True)
                native_control(review, "AXButton", apply, press=True)
                await_heading("Local commit created")
                need(git("rev-parse", "HEAD^") == head and git("rev-list", "--count", "HEAD") == b"2\n"
                     and git("show", "-s", "--format=%an%n%ae%n%s", "HEAD").decode().splitlines() == [author, email, message]
                     and git("diff", "--name-only", "HEAD^", "HEAD") == b"README.md\n"
                     and git("show", "HEAD:README.md") == initial + marker
                     and git("diff", "--cached", "--name-only") == b""
                     and readme.read_bytes() == initial + marker, "commit-parent-scope-or-contents")
                observation["exactCommitMetadataTreeParentAndWorktree"] = True
                return

            if suite == "git-stale-stage":
                proof = results["gitStaleStage"] = {}
                need(git("diff", "--cached", "--name-only") == b"pre-staged-owner.bin\n" and
                     git("show", ":pre-staged-owner.bin") == unrelated_body, "fixture-unrelated-index-identity")
                press_after_settlement("Local Git changes", "Review files to stage")
                await_heading("Review files to stage")
                need(native_control(review, "AXStaticText", "README.md")["matches"] == 1
                     and native_control(review, "AXStaticText", "pre-staged-owner.bin")["matches"] == 0,
                     "unexpected-git-stage-review-roster")
                need(native_control(review, "AXButton", "Stage these files")["enabled"] is False,
                     "stage-ready-without-consent")
                native_control(review, "AXCheckBox", reviewed, press=True)
                need(native_control(review, "AXCheckBox", reviewed).get("checked") is True,
                     "original-git-stage-consent")
                changed = initial + marker + b"Concurrent disposable working-file replacement.\n"
                with readme.open("wb") as stream:
                    stream.write(changed)
                    stream.flush()
                    os.fsync(stream.fileno())
                proof["fixtureFileChangedAfterReview"] = True
                save()
                admitted = native_control(review, "AXButton", "Stage these files")
                if admitted.get("enabled") is True:
                    native_control(review, "AXButton", "Stage these files", press=True)
                    proof["oneApplySentForExactOriginalReview"] = True
                end = time.monotonic() + 55
                while time.monotonic() < end:
                    safe = {"Git action did not complete", "Git action needs attention", "Git recovery is needed"}
                    labels = [label for label in safe if native_control(status_region, "AXHeading", label)["matches"] == 1]
                    if labels:
                        proof["originalRefusal"] = labels
                        break
                    if not admitted.get("enabled") and native_control(review, "AXButton", "Stage these files").get("enabled") is False:
                        proof["reviewDisabledAfterStaleObservation"] = True
                        break
                    check = native_control(status_region, "AXButton", "Check action")
                    if check.get("enabled") is True:
                        native_control(status_region, "AXButton", "Check action", press=True)
                    need(native_control(status_region, "AXHeading", "Selected files staged")["matches"] == 0,
                         "unreviewed-changed-file-reported-staged")
                    time.sleep(1.5)
                need(git("rev-parse","HEAD") == head and git("diff", "--cached", "--name-only") == b"pre-staged-owner.bin\n"
                     and git("show", ":pre-staged-owner.bin") == unrelated_body and unrelated.read_bytes() == unrelated_body
                     and readme.read_bytes() == changed, "stale-apply-changed-worktree-branch-or-original-index")
                need(proof.get("originalRefusal") or proof.get("reviewDisabledAfterStaleObservation"),
                     "no-original-refusal-or-disabled-review-evidence")
                proof["reviewRefusedAndOriginalStagedBytesPreserved"] = True
                return

            press_after_settlement("Local Git changes", "Review files to stage")
            await_heading("Review files to stage")
            need(native_control(review, "AXStaticText", "README.md")["matches"] == 1, "git-stage-review-path")
            apply = native_control(review, "AXButton", "Stage these files")
            need(apply["matches"] == 1 and apply["enabled"] is False,
                 "git-index-apply-enabled-without-consent")
            native_control(status_region, "AXButton", "Close review, keep draft", press=True)
            verify_change(False)
            fact["cancelPreservedIndexAndHead"] = True
            press_after_settlement("Local Git changes", "Review files to stage")
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
            # Apply invalidates the reader's captured project revision. The
            # ordinary UI requires a fresh read admission before Refresh.
            read_status = "Local Git read status"
            changes = "Local Git changes"
            press_after_settlement(read_status, "Check local Git access")
            press_after_settlement("Local Git changes", "Refresh changes")
            next_stage_read = time.monotonic() + 2

            def staged_observation():
                nonlocal next_stage_read
                # The earlier read's finished title can survive into Refresh.
                # The changed and staged count requires the new file revision.
                if native_control(changes, "AXStaticText", "1 changed · 1 staged")["matches"] == 1:
                    return True
                if time.monotonic() >= next_stage_read:
                    check = native_control(read_status, "AXButton", "Check read")
                    if check.get("enabled") is True:
                        native_control(read_status, "AXButton", "Check read", press=True)
                        fact["stageReadStatusChecks"] = fact.get("stageReadStatusChecks", 0) + 1
                    next_stage_read = time.monotonic() + 5
                return False

            until(staged_observation, 60, "git-index-current-staged-observation")
            fact["currentStagedObservation"] = True
            press_after_settlement(status_region, "Check local Git actions")
            press_after_settlement(changes, "Review files to unstage")
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

        if suite == "git-commit":
            git("add", "--", "README.md")
        unrelated = project / "pre-staged-owner.bin"
        unrelated_body = bytes(range(256)) * 4
        if suite == "git-stale-stage":
            with unrelated.open("xb") as stream:
                stream.write(unrelated_body)
            git("add", "--", unrelated.name)
        before = git("status", "--porcelain=v1")
        head = git("rev-parse", "HEAD")
        expected_state = b"M  README.md\n" if suite == "git-commit" else b" M README.md\n"
        if suite == "git-stale-stage":
            expected_state += b"A  pre-staged-owner.bin\n"
        need(before == expected_state, "exact-synthetic-worktree-change")
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
            if suite in {"git-index", "git-commit", "git-stale-stage"}:
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
            if suite != "git-stale-stage":
                need(readme.read_bytes() == initial + marker, "git-read-changed-the-synthetic-input")
                readme.write_bytes(initial)

    def installation_audit():
        receipt = PRODUCT / "installation-v2.json"
        before = call("/usr/bin/sudo", "-n", "/bin/cat", str(receipt)).stdout
        release = json.loads(before)["current"]["release"]
        need(release["packageSha256"] == results["packageSha256"], "audit-original-installed-receipt")
        ui.page("Build tools")
        ui.click("About this installation", contains=True)
        ui.node("Where the app lives", category="heading", contains=True)
        ui.click("Check installation", category="button")
        until(lambda: any(row["text"] == "Read-only correspondence observed" for row in
                         ui.command("tree.snapshot", limit=800)["nodes"] if row["visible"]),
              35, "original-installation-check-did-not-settle")
        ui.node("matched their protected inventory", category="statictext", contains=True)
        after = call("/usr/bin/sudo", "-n", "/bin/cat", str(receipt)).stdout
        need(after == before and ui.payload_pid(), "read-only-check-changed-installation")
        need(all(file_hash(project / name) == digest for name, digest in original.items()),
             "read-only-check-changed-project")
        results["installationAudit"] = {"protectedInventoryCorrespondence": True, "sameReceipt": True,
                                        "sameProjectInputs": True}

    def github_input_boundaries():
        ui.page("GitHub")
        # The tasks interface may default to a different tab.
        _, tab = ui.node("Connect", category="radiobutton")
        if tab["bounds"]:
            ui.click("Connect", category="radiobutton")
        name = "Your app’s GitHub repository"
        ui.edit(name, "https://example.invalid/wrong/repository")
        ui.node("A malformed target cannot start a connection.", category="statictext", contains=True)
        _, device = ui.node("Get a GitHub sign-in code", category="button")
        need(not device["enabled"], "malformed-target-enabled-github-device-code")
        ui.click("Advanced: use a personal access token", category="disclosuretriangle")
        _, entry = ui.node("Token connection unavailable", category="button")
        need(not entry["enabled"], "malformed-target-enabled-token-entry")
        ui.click(name, category="textfield", contains=True)
        ui.keys("command", "a")
        ui.keys("backspace")
        need(ui.node(name, category="textfield", contains=True)[1]["text"] == "", "empty-github-target")
        need(all(file_hash(project / name) == digest for name, digest in original.items()),
             "github-input-refusal-wrote-project")
        results["gitInputRefusals"] = {"malformedTargetNoDeviceCode": True, "malformedTargetNoTokenEntry": True,
                                       "emptyClearsDraft": True, "projectInputsUnchanged": True}

    def github_invalid_token():
        ui.page("GitHub")
        ui.click("Connect", category="radiobutton", region="GitHub tasks")
        ui.edit("Your app’s GitHub repository", "Apdelrahman1911/mobile-release-kit")
        # Project selection retires the previous connection help revision.
        # Use its explicit supported read-only reload before readiness or input.
        reload_label = "Reload service and connection guidance"
        if any(row["name"] == reload_label and row["enabled"] and row["visible"]
               for row in ui.command("tree.snapshot", limit=800)["nodes"]):
            ui.click(reload_label, category="button")
        until(lambda: any(row["name"] == "Your app’s GitHub repository" and row["visible"] and row["enabled"]
                          and row["text"] == "Apdelrahman1911/mobile-release-kit"
                          for row in ui.command("tree.snapshot", limit=800)["nodes"]),
              25, "original-repository-not-restored-after-guidance-reload")
        candidates = [row for row in ui.command("tree.snapshot", limit=800)["nodes"] if row["visible"]
                      and row["name"] == "Connect for read-only observations"]
        if not candidates:
            _, summary = ui.reveal("Advanced: use a personal access token",category="disclosuretriangle")
            box=summary["bounds"]
            need(box["width"]>=48 and box["height"]>=12,"password-disclosure-in-original-window")
            ui.command("pointer.click",x=box["x"]+min(30,box["width"]//2),y=box["y"]+box["height"]//2)
        region = "GitHub connection and observations"
        command = "Connect for read-only observations"
        token_label = "Advanced session-only user token"
        def entry_observed():
            rows = [r for r in ui.command("tree.snapshot", limit=800)["nodes"] if r["visible"]]
            names = {label for row in rows for label in (row["name"],row["text"])}
            if command in names:
                return "available"
            if "Token entry is unavailable in this build." in names:
                return "build-gated"
            return None
        entry = until(entry_observed, 38, "valid-repository-did-not-admit-synthetic-token-entry")
        need(entry == "available", "installed-app-disabled-token-entry")
        # There is no authorized or real credential in this workspace.
        # This single deliberately invalid value is for one denial check.
        ui.reveal(command,category="button",region=region,enabled=True)
        tree=ui.command("tree.snapshot",limit=800)
        buttons=[row for row in tree["nodes"] if row["role"]=="button" and row["name"]==command
                 and row["enabled"] and row["visible"]]
        need(len(buttons)==1,"unique-private-token-submit")
        prefix=buttons[0]["id"].rsplit(".",1)[0] + "."
        form=[row for row in tree["nodes"] if row["id"].startswith(prefix) and row["visible"]]
        need(any(row["name"]== "Help: "+token_label for row in form) and
             any("gated password field" in row["text"] for row in form),"password-form-identity")
        fields=[row for row in form if row["role"] in {"textfield","securetextfield"}
                and row["name"] in {"",token_label} and row["enabled"] and row["text"]==""]
        need(len(fields)==1 and fields[0]["bounds"],"unique-blank-password-field-in-original-form")
        ui.command("element.click",snapshot_id=tree["snapshot_id"],id=fields[0]["id"])
        ui.command("text.insert",text="ghp_" + ("0" * 36))
        ui.click(command, category="button", region=region)
        fact = results["gitInputRefusals"] = {"syntheticInertValueSubmittedOnce":True}
        save()
        def denied():
            rows = ui.command("tree.snapshot", limit=800)["nodes"]
            labels = {label for node in rows if node["visible"] for label in (node["text"],node["name"])}
            need(not {"Connected for read-only checks","Account verified — repository not yet checked"} & labels,
                 "invalid-synthetic-token-established-connection")
            return any("Authentication was refused. Retire the original request before explicitly authenticating again." in label
                       for label in labels)
        until(denied, 45, "original-invalid-token-denial-unobserved")
        fact["installedAppReportedAuthenticationDenied"] = True
        ui.click("Check connection status", category="button", region=region)
        _, disconnect = ui.node("Disconnect original connection", category="button", region=region)
        if disconnect["enabled"]:
            ui.click("Disconnect original connection", category="button", region=region)
        summary="Connection details, workflow checks & help"
        if not any("No retained native session." in r["text"] for r in ui.command("tree.snapshot",limit=800)["nodes"] if r["visible"]):
            _, disclosure=ui.reveal(summary,category="disclosuretriangle")
            box=disclosure["bounds"]
            ui.command("pointer.click",x=box["x"]+min(30,box["width"]//2),y=box["y"]+box["height"]//2)
        def original_denial_clean():
            rows=ui.command("tree.snapshot",limit=800)["nodes"]
            no_session=any("No retained native session." in row["text"] for row in rows if row["visible"])
            stopped=[row for row in rows if row["visible"] and row["role"]=="button"
                     and row["name"]=="Disconnect original connection"]
            return no_session and len(stopped)==1 and not stopped[0]["enabled"]
        until(original_denial_clean,18,"original-invalid-token-cleanup-unconfirmed")
        need(all(file_hash(project / path) == digest for path,digest in original.items()),
             "invalid-token-mutated-project")
        fact["noSessionRetainedAndProjectUnchanged"] = True


    try:
        if scenario("native-console-admission", start_observation) and scenario("project-picker-and-saved-config", select_project):
            exercise = {**dict.fromkeys(VAULT_SUITES, vault_journey),
                        **dict.fromkeys(VERSION_FAULTS, version_fault_journey),
                        **dict.fromkeys(GIT_CHANGES, git_observation),
                        "git-init": git_initialize,
                        "installation-audit": installation_audit,
                        "github-malformed-target": github_input_boundaries,
                        "github-synthetic-denial": github_invalid_token}.get(suite, aab_readback)
            scenario(SCENARIOS[suite], exercise)
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
