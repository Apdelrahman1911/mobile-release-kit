import Darwin
import Foundation
import XCTest

#if !os(macOS) || !arch(arm64)
#error("This external UI scenario requires a fresh hosted ARM64 macOS 26 job.")
#endif

// Tests the unchanged ordinary app, never the in-process engineering observer.
// This is UI evidence, not POSIX exit status or all-worker/descriptor finality.
final class NormalAppUITests: XCTestCase {
    private enum Refusal: Error { case condition(String) }
    @MainActor private var launchedApplication: XCUIApplication?
    @MainActor private var normalQuitObserved = false

    @MainActor private func require(_ value: Bool, _ reason: String) throws {
        guard value else { throw Refusal.condition(reason) }
    }

    @MainActor private func unique(_ query: XCUIElementQuery, _ reason: String) throws -> XCUIElement {
        try require(query.count == 1, reason)
        return query.element(boundBy: 0)
    }

    @MainActor private func click(_ query: XCUIElementQuery, _ reason: String) throws {
        let element = try unique(query, reason)
        try require(element.isEnabled && element.isHittable, reason)
        element.click()
    }

    @MainActor private func dashboard(_ renderer: XCUIElement) throws {
        let heading = renderer.staticTexts.matching(identifier: "Good releases start here.")
        try require(heading.element(boundBy: 0).waitForExistence(timeout: 5), "dashboard heading did not render")
        _ = try unique(heading, "dashboard heading is ambiguous")
        let open = try unique(renderer.buttons.matching(identifier: "Open project folder"),
                              "ordinary first-party project control is missing or ambiguous")
        let ready = XCTNSPredicateExpectation(predicate: NSPredicate(format: "enabled == true AND hittable == true"), object: open)
        try require(XCTWaiter.wait(for: [ready], timeout: 5) == .completed, "ordinary project control is not usable")
        try require(renderer.staticTexts.matching(identifier: "BROWSER PREVIEW — EXAMPLE DATA ONLY").count == 0,
                    "browser-preview data is not ordinary-app evidence")
    }

    @MainActor private func quitSheet(_ app: XCUIApplication, _ window: XCUIElement) throws -> XCUIElement {
        try require(window.sheets.count == 0, "an unrelated sheet is already present")
        let menuBar = try unique(app.menuBars, "application menu bar is missing or ambiguous")
        try click(menuBar.menuBarItems.matching(identifier: "File"), "the application's File menu is unavailable")
        // Scoped to this application's opened menu bar, never a global keystroke.
        try click(menuBar.menuItems.matching(identifier: "Quit"), "the File menu has no unique Quit action")
        let query = window.sheets
        try require(query.element(boundBy: 0).waitForExistence(timeout: 5), "normal Quit did not present its native sheet")
        let sheet = try unique(query, "normal Quit sheet is ambiguous")
        _ = try unique(sheet.staticTexts.matching(identifier: "Quit and discard unsaved drafts?"),
                       "unexpected confirmation sheet")
        try require(sheet.buttons.count == 2, "unexpected actions in the normal Quit sheet")
        _ = try unique(sheet.buttons.matching(identifier: "Cancel"), "normal Quit has no unique Cancel button")
        _ = try unique(sheet.buttons.matching(identifier: "Quit"), "normal Quit has no unique affirmative button")
        return sheet
    }

    @MainActor
    func testLaunchCancelAndQuit() throws {
        continueAfterFailure = false
        // XCTest rounds to whole minutes; this is an actual 60-second setting,
        // not a claimed exact 90-second setting that silently becomes 120.
        executionTimeAllowance = 60
        let context = ProcessInfo.processInfo.environment
        try require(context["MRK_NORMAL_UI_HOSTED_JOB"] == "github-hosted-macos26-arm64",
                    "this scenario is not admitted on a shared or personal desktop")
        try require(getuid() != 0 && getuid() == geteuid() && getgid() == getegid(),
                    "the ordinary application must run as the original nonroot account")
        try require(ProcessInfo.processInfo.operatingSystemVersion.majorVersion == 26
                    && NSUserName() == "runner" && NSHomeDirectory() == "/Users/runner",
                    "unsupported hosted platform/account")
        let applicationSource = context["MRK_NORMAL_UI_APPLICATION_SOURCE"] ?? ""
        let harnessSource = context["MRK_NORMAL_UI_HARNESS_SOURCE"] ?? ""
        let hexadecimal = CharacterSet(charactersIn: "0123456789abcdef")
        try require(applicationSource.utf8.count == 40 && applicationSource.unicodeScalars.allSatisfy(hexadecimal.contains)
                    && applicationSource == harnessSource,
                    "this same-build scenario needs exact application and harness source bindings")

        let url = URL(fileURLWithPath: "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app",
                      isDirectory: true)
        try require(Bundle(url: url)?.bundleIdentifier == "dev.mobile-release-kit.desktop"
                    && (Bundle(url: url)?.object(forInfoDictionaryKey: "CFBundleExecutable") as? String) == "mobile-release-kit-desktop",
                    "the exact ordinary installed application is missing")
        // The preceding Installer/readback gate binds the bytes to the normal
        // Cargo binary. A bundle identifier by itself is NOT that proof.
        let app = XCUIApplication(url: url)
        try require(app.state == .notRunning, "application already running; launch must not terminate an existing instance")
        app.launchArguments = []
        // Apple's launchEnvironment API permits removal, not just overrides.
        // No token, project path, development runtime or observer flag is passed.
        app.launchEnvironment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": NSHomeDirectory(), "USER": NSUserName(), "LOGNAME": NSUserName(),
            "TMPDIR": NSTemporaryDirectory(), "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8", "TZ": "UTC"
        ]
        // Register cleanup only AFTER the notRunning precondition. A refused
        // occupied application is never terminated by this test's teardown.
        launchedApplication = app
        app.launch() // Exactly once; no activate/relaunch/retry or external PID.
        try require(app.wait(for: .runningForeground, timeout: 5), "ordinary app did not enter the foreground")
        try require(app.windows.element(boundBy: 0).waitForExistence(timeout: 5), "ordinary app has no visible main window")
        let window = try unique(app.windows, "ordinary main window is ambiguous")
        try require(window.isHittable, "ordinary main window is not usable")
        let renderer = try unique(window.webViews, "ordinary first-party renderer is missing or ambiguous")
        try dashboard(renderer)

        let first = try quitSheet(app, window)
        try click(first.buttons.matching(identifier: "Cancel"), "normal Quit Cancel is unavailable")
        let dismissed = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: first)
        try require(XCTWaiter.wait(for: [dismissed], timeout: 5) == .completed, "Cancel did not dismiss the normal Quit sheet")
        try require(app.state == .runningForeground && window.exists, "Cancel did not preserve the running application")
        try dashboard(renderer)
        // Prove renderer responsiveness after Cancel without selecting a project,
        // opening a file picker, changing configuration or invoking a Store.
        try click(renderer.buttons.matching(identifier: "Project settings"), "post-Cancel navigation is unavailable")
        try require(renderer.staticTexts.matching(identifier: "A little clarity before the next release.")
                    .element(boundBy: 0).waitForExistence(timeout: 5), "post-Cancel settings navigation failed")
        try click(renderer.buttons.matching(identifier: "Dashboard"), "post-Cancel Dashboard navigation is unavailable")
        try dashboard(renderer)

        let second = try quitSheet(app, window)
        try click(second.buttons.matching(identifier: "Quit"), "normal affirmative Quit is unavailable")
        try require(app.wait(for: .notRunning, timeout: 10), "the genuine Quit action did not reach notRunning")
        normalQuitObserved = true
        // Not final until the original XCTest/xcodebuild result also succeeds.
        print("MRK_MACOS_NORMAL_UI=launch-render-cancel-navigation-quit-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }

    override func tearDown() async throws {
        var cleanupFailure: Error?
        do {
            try await MainActor.run {
                guard let app = launchedApplication else { return }
                if app.state != .notRunning {
                    // Failure cleanup only, through the same launched-app proxy in
                    // the exclusive disposable job. Never accepted as normal Quit.
                    app.terminate()
                    guard app.wait(for: .notRunning, timeout: 5) else {
                        throw Refusal.condition("task-owned framework cleanup did not reach notRunning")
                    }
                    throw Refusal.condition("framework cleanup was required; normal Quit is not accepted")
                }
                guard normalQuitObserved else {
                    throw Refusal.condition("application stopped without completing the normal Quit scenario")
                }
            }
        } catch { cleanupFailure = error }
        do { try await super.tearDown() } catch {
            if cleanupFailure == nil { cleanupFailure = error }
        }
        if let cleanupFailure { throw cleanupFailure }
    }
}
