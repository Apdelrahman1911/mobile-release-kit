import AppKit
import CryptoKit
import Darwin
import Foundation
import XCTest

#if !os(macOS) || !(arch(arm64) || arch(x86_64))
#error("This external UI scenario requires a fresh hosted native64 macOS 26 job.")
#endif

// Tests the unchanged ordinary app, never the in-process engineering observer.
// This is UI evidence, not POSIX exit status or all-worker/descriptor finality.
final class NormalAppUITests: XCTestCase {
    private enum Refusal: Error { case condition(String) }
    private enum RequireCheck: String { case condition, singleton, actionable }
    private enum DashboardReason: String {
        case loading, notLoaded = "not-loaded", bridgeUnavailable = "bridge-unavailable"
        case selectionUnavailable = "selection-unavailable", selectionInProgress = "selection-in-progress"
        case shuttingDown = "shutting-down"
        case ownerOfflinePreflight = "owner-offline-preflight", ownerAndroidBuild = "owner-android-build"
        case ownerIOSArchive = "owner-ios-archive", ownerProjectRecovery = "owner-project-recovery"
        case ownerGitHubPreflight = "owner-github-preflight", ownerGitHubRelease = "owner-github-release"
        case ownerProjectPath = "owner-project-path", ownerSavedVersionEdit = "owner-saved-version-edit"
        case ownerMetadataImages = "owner-metadata-images"
        case otherOrUnobserved = "other-or-unobserved", ambiguous
    }
    private enum DashboardWaiter: String {
        case completed, timedOut = "timed-out", incorrectOrder = "incorrect-order"
        case invertedFulfillment = "inverted-fulfillment", interrupted, unknown
        init(_ result: XCTWaiter.Result) {
            switch result {
            case .completed: self = .completed
            case .timedOut: self = .timedOut
            case .incorrectOrder: self = .incorrectOrder
            case .invertedFulfillment: self = .invertedFulfillment
            case .interrupted: self = .interrupted
            @unknown default: self = .unknown
            }
        }
    }
    private struct DashboardSnapshot {
        let ordinal: UInt8
        let enabled: Bool
        let hittable: Bool
        let reason: DashboardReason
    }
    @MainActor private var packagedRequireDiagnosticActive = false
    @MainActor private var packagedRequireDiagnosticEmitted = false
    @MainActor private var engineeringRequireDiagnosticActive = false
    @MainActor private var engineeringRequireDiagnosticEmitted = false
    @MainActor private var originalLaunch: OrdinaryLaunch?
    @MainActor private var caseClock: CaseClock?
    @MainActor private var normalQuitObserved = false
    @MainActor private var entryGateObservation: GateObservation?
    // Only the persistence case may retain a completed first lifetime and open
    // a second. Active custody is never cleared without retaining its originals.
    @MainActor private var completedPersistenceLifetime: CompletedPersistenceLifetime?
    @MainActor private struct CompletedPersistenceLifetime {
        let owner: OrdinaryLaunch
        let gate: GateObservation
        let normalQuit: Bool // Includes the first successful consuming gate close.
    }

    // One immutable monotonic case end, started before admission. Stage limits
    // may narrow it; a failure or restored stage limit never renews work.
    @MainActor private final class CaseClock {
        let deadline: TimeInterval
        private var last: TimeInterval
        private var unusable = false
        private(set) var firstFailure: String?
        init(seconds: TimeInterval) throws {
            let now = ProcessInfo.processInfo.systemUptime
            guard now.isFinite, now >= 0, seconds == 60 || seconds == 300,
                  (now + seconds).isFinite, now + seconds > now else {
                throw Refusal.condition("case clock unavailable")
            }
            last = now
            deadline = now + seconds
        }
        func fail(_ reason: String) -> Refusal {
            if firstFailure == nil { firstFailure = reason }
            return .condition(firstFailure!)
        }
        private func now() throws -> TimeInterval {
            guard !unusable else { throw fail("case clock unavailable") }
            let value = ProcessInfo.processInfo.systemUptime
            guard value.isFinite, value >= last else {
                unusable = true
                throw fail("case clock moved backwards or became unavailable")
            }
            last = value
            return value
        }
        func remaining(_ maximum: TimeInterval, before end: TimeInterval? = nil,
                       cleanup: Bool = false) throws -> TimeInterval {
            if !cleanup, let firstFailure { throw Refusal.condition(firstFailure) }
            guard maximum.isFinite, maximum > 0, end == nil || end!.isFinite else {
                throw fail("invalid bounded wait")
            }
            let left = min(deadline, end ?? deadline) - (try now())
            guard left.isFinite, left > 0 else { throw fail("original case or stage deadline elapsed") }
            return min(maximum, left)
        }
        func end(within maximum: TimeInterval, cleanup: Bool = false) throws -> TimeInterval {
            // One observed start; never add an elapsed allowance to a later
            // timestamp and thereby grow this absolute interval.
            if !cleanup, let firstFailure { throw Refusal.condition(firstFailure) }
            let start = try now()
            guard maximum.isFinite, maximum > 0, start < deadline,
                  (start + maximum).isFinite else { throw fail("original case deadline elapsed") }
            return min(deadline, start + maximum)
        }
        func progress(until end: TimeInterval, cleanup: Bool = false) throws {
            let slice = try remaining(0.02, before: end, cleanup: cleanup)
            // AppKit's time-varying properties need actual main-run-loop turns.
            _ = RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: slice))
        }
    }

    // Only this lock-protected transport crosses NSWorkspace's concurrent
    // completion queue. No AppKit property is inspected off the main actor.
    // @unchecked Sendable covers this private NSLock discipline, not app safety.
    private final class LaunchReply: @unchecked Sendable {
        struct Snapshot {
            let entries: Int
            let bodies: Int
            let first: NSRunningApplication?
            let error: Bool
        }
        private let lock = NSLock()
        private var entries = 0
        private var bodies = 0
        private var first: NSRunningApplication?
        private var error = false
        func enter() -> Int {
            lock.lock(); defer { lock.unlock() }
            entries = min(2, entries + 1)
            return entries
        }
        func body(_ ticket: Int, application: NSRunningApplication?, failed: Bool) {
            lock.lock(); defer { lock.unlock() }
            if ticket == 1 {
                first = application // Retain before ANY fallible validation.
                error = failed
            }
            bodies = min(2, bodies + 1)
        }
        func snapshot() -> Snapshot {
            lock.lock(); defer { lock.unlock() }
            return Snapshot(entries: entries, bodies: bodies, first: first, error: error)
        }
    }

    @MainActor private final class OrdinaryLaunch {
        static let outerURL = URL(fileURLWithPath: "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app", isDirectory: true)
        static let payloadURL = outerURL.appendingPathComponent("Contents/Helpers/MobileReleaseKitPayload.app", isDirectory: true)
        private let clock: CaseClock
        private let profile: LaunchProfile
        private let reply = LaunchReply()
        private var original: NSRunningApplication?
        private var requested = false
        private var handoffs = 0
        private var launchEnd: TimeInterval?
        private var workClosed = false
        private var cleanupEnd: TimeInterval?
        private var cleaning = false
        private var normalRequested = false
        private var normalReturned: Bool?
        private var forceRequested = false
        private var forceReturned: Bool?
        private var cleanupTerminationObserved = false

        init(clock: CaseClock, profile: LaunchProfile = .ordinary) {
            self.clock = clock
            self.profile = profile
        }

        private func handoff() {
            handoffs = min(2, handoffs + 1)
            let value = reply.snapshot()
            // Main handoffs may reorder: ticket 2 can precede ticket 1's
            // body. Take only ticket 1's retained value whenever available,
            // even after duplicate failure; arrival order grants no authority.
            if original == nil { original = value.first }
            do {
                guard let launchEnd, !workClosed else { throw clock.fail("late original is cleanup-only") }
                _ = try clock.remaining(15, before: launchEnd)
                try callbackHealthy()
            } catch {
                workClosed = true
                _ = clock.fail("launch completion refused")
            }
            // If teardown already started, a late reference can consume only
            // its SAME original cleanup budget. No new budget or UI authority.
            if let cleanupEnd, !cleaning { try? driveCleanup(until: cleanupEnd) }
        }

        private func callbackHealthy(complete: Bool = false) throws {
            let value = reply.snapshot()
            guard requested, value.entries <= 1, value.bodies <= 1, handoffs <= 1 else {
                throw clock.fail("duplicate or unrequested launch completion")
            }
            if handoffs == 1 {
                guard value.entries == 1, value.bodies == 1, !value.error, original != nil else {
                    throw clock.fail("launch completion has error or no original")
                }
            }
            if complete {
                guard value.entries == 1, value.bodies == 1, handoffs == 1 else {
                    throw clock.fail("original launch completion is incomplete")
                }
            }
        }
        func healthy() throws {
            guard !workClosed else { throw clock.fail("ordinary launch work is closed") }
            try callbackHealthy()
            _ = try clock.remaining(1)
        }
        private func payloadIdentity() throws -> NSRunningApplication {
            switch profile {
            case .ordinary:
                guard let original,
                      original.bundleURL?.path == Self.payloadURL.path,
                      original.executableURL?.path == Self.payloadURL.appendingPathComponent("Contents/MacOS/mobile-release-kit-desktop").path,
                      original.bundleIdentifier == "dev.mobile-release-kit.desktop" else {
                    throw clock.fail("original running reference is not the fixed payload")
                }
                return original
            case .engineeringMain(let work):
                let app = work.appendingPathComponent("Mobile Release Kit.app", isDirectory: true)
                guard let original, original.bundleURL?.path == app.path,
                      original.executableURL?.path == app.appendingPathComponent("Contents/MacOS/mobile-release-kit-desktop").path,
                      original.bundleIdentifier == "dev.mobile-release-kit.engineering-ui" else {
                    throw clock.fail("original running reference is not the fixed engineering main")
                }
                return original
            }
        }

        func requestAndAwait() throws {
            guard !requested, Thread.isMainThread else { throw clock.fail("ordinary launch is not one main-thread request") }
            launchEnd = try clock.end(within: 15)
            let configuration = NSWorkspace.OpenConfiguration()
            configuration.activates = true
            configuration.addsToRecentItems = false
            configuration.createsNewApplicationInstance = true
            configuration.allowsRunningApplicationSubstitution = false
            configuration.promptsUserIfNeeded = false
            configuration.arguments = []
            let requestURL: URL
            switch profile {
            case .ordinary:
                // No environment override: the unchanged ordinary entry derives its
                // own eight-entry environment and inherits the original gate once.
                requestURL = Self.outerURL
            case .engineeringMain(let work):
                requestURL = work.appendingPathComponent("Mobile Release Kit.app", isDirectory: true)
                configuration.environment = [
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner", "LOGNAME": "runner",
                    "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",
                    "TMPDIR": work.appendingPathComponent("normal-ui/tmp", isDirectory: true).path + "/",
                    "MRK_DESKTOP_DEV_PYTHON": work.appendingPathComponent("runtime/python/bin/python3").path,
                    "MRK_DESKTOP_DEV_CORE": work.appendingPathComponent("runtime/core.zip").path,
                ]
            }
            requested = true
            let mailbox = reply
            NSWorkspace.shared.openApplication(at: requestURL, configuration: configuration) { [self, mailbox] application, error in
                let ticket = mailbox.enter()
                mailbox.body(ticket, application: application, failed: error != nil)
                DispatchQueue.main.async { self.handoff() }
            }
            do {
                guard let launchEnd else { throw clock.fail("original launch deadline missing") }
                while true {
                    try clock.progress(until: launchEnd)
                    try healthy()
                    if handoffs == 1 {
                        let app = try payloadIdentity()
                        guard !app.isTerminated else { throw clock.fail("original terminated before UI admission") }
                        if app.isFinishedLaunching && app.isActive {
                            try callbackHealthy(complete: true)
                            _ = try clock.remaining(15, before: launchEnd)
                            return
                        }
                    }
                }
            } catch {
                workClosed = true
                _ = clock.fail("ordinary launch failed or exceeded its original deadline")
                throw error
            }
        }

        func observeNormalTermination(until end: TimeInterval) throws {
            while true {
                try clock.progress(until: end)
                try healthy()
                let app = try payloadIdentity()
                if app.isTerminated { try acceptTerminal(); return }
            }
        }
        func acceptTerminal() throws {
            try healthy()
            try recheckCompletedTerminal()
        }
        // An already accepted first lifetime gets no second cleanup window or
        // stop request. Its retained callback/terminal facts can still fail,
        // even when another lifetime has already latched a case failure.
        func recheckCompletedTerminal() throws {
            try callbackHealthy(complete: true)
            let app = try payloadIdentity()
            guard !workClosed, app.isTerminated, !normalRequested, !forceRequested else {
                throw clock.fail("same original termination without failure cleanup is required")
            }
        }

        private func driveCleanup(until end: TimeInterval) throws {
            guard !cleaning else { return }
            cleaning = true; defer { cleaning = false }
            var graceEnd: TimeInterval?
            while true {
                _ = try clock.remaining(5, before: end, cleanup: true)
                if let original {
                    // The only allowed cleanup receiver: never a lookup, proxy,
                    // PID/signal, second callback's app or a replacement owner.
                    if original.isTerminated { cleanupTerminationObserved = true; return }
                    if !normalRequested {
                        normalRequested = true
                        normalReturned = original.terminate()
                        graceEnd = min(end, try clock.end(within: 1, cleanup: true))
                    }
                    if !forceRequested {
                        let grace = graceEnd ?? end
                        do { _ = try clock.remaining(1, before: grace, cleanup: true) }
                        catch {
                            _ = try clock.remaining(5, before: end, cleanup: true)
                            forceRequested = true
                            forceReturned = original.forceTerminate()
                        }
                    }
                }
                try clock.progress(until: end, cleanup: true)
            }
        }
        func tearDown(normalQuit: Bool) throws {
            if normalQuit {
                do { try acceptTerminal(); return }
                catch { _ = clock.fail("terminal original changed before teardown") }
            }
            workClosed = true
            _ = clock.fail("normal UI Quit was not accepted")
            // A failed clock/work stage cannot be repaired. Cleanup may use only
            // remaining case time, at most five seconds TOTAL, including a late
            // callback and normal grace. Retain unknown state on exhaustion.
            do {
                if cleanupEnd == nil { cleanupEnd = try clock.end(within: 5, cleanup: true) }
                if let cleanupEnd { try driveCleanup(until: cleanupEnd) }
            } catch { /* Unknown remains unknown; do not retry or renew. */ }
            let normal = normalReturned.map { $0 ? "true" : "false" } ?? "null"
            let forced = forceReturned.map { $0 ? "true" : "false" } ?? "null"
            print("MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=\(normalRequested);normalReturned=\(normal);forceRequested=\(forceRequested);forceReturned=\(forced);originalTerminated=\(cleanupTerminationObserved);unknownStateRetained=\(!cleanupTerminationObserved)")
            throw clock.fail("failure cleanup is never normal Quit evidence")
        }
    }

    @MainActor private func beginCase(seconds: TimeInterval) throws {
        try require(caseClock == nil && journeyDeadline == nil && originalLaunch == nil, "case deadline cannot be reset")
        let clock = try CaseClock(seconds: seconds)
        caseClock = clock
        journeyDeadline = clock.deadline
    }

    @MainActor private func launchOrdinaryApplication() throws -> XCUIApplication {
        _ = try remaining(15)
        guard let clock = caseClock else { throw Refusal.condition("original case clock missing") }
        try require(originalLaunch == nil && entryGateObservation == nil && !normalQuitObserved
                    && ProcessInfo.processInfo.environment["MRK_ENGINEERING_UI_WORK"] == nil,
                    "a new ordinary launch requires empty active custody and no engineering profile")
        let outer = XCUIApplication(url: OrdinaryLaunch.outerURL)
        let monitor = XCUIApplication(url: OrdinaryLaunch.payloadURL)
        try require(outer.state == .notRunning && monitor.state == .notRunning,
                    "occupied outer or payload must not be launched, adopted or terminated")
        let gate = GateObservation()
        entryGateObservation = gate
        try gate.openOnce()
        try gate.probe(busy: false)
        let owner = OrdinaryLaunch(clock: clock)
        originalLaunch = owner // Custody before the one fallible request.
        try owner.requestAndAwait()
        try gate.probe(busy: true)
        try owner.healthy()
        // This URL proxy is monitoring/UI only, NOT a public original-PID attach.
        // Never launch, activate, open or terminate it.
        return monitor
    }

    @MainActor private func completeNormalQuit(_ app: XCUIApplication) throws {
        guard let clock = caseClock, let owner = originalLaunch, let gate = entryGateObservation else {
            throw Refusal.condition("normal Quit original custody missing")
        }
        let end = try clock.end(within: 10)
        try require(app.wait(for: .notRunning, timeout: try clock.remaining(10, before: end)),
                    "genuine Quit did not stop the payload UI proxy")
        try owner.observeNormalTermination(until: end) // SAME ten seconds, not another ten.
        try require(app.state == .notRunning, "payload UI proxy changed after original termination")
        try gate.probe(busy: false)
        try gate.closeOriginal()
        try owner.acceptTerminal()
        normalQuitObserved = true
    }

    @MainActor private func acceptFinalScenario() throws {
        try require(completedPersistenceLifetime == nil, "two-lifetime persistence requires its own final acceptance")
        try require(normalQuitObserved, "normal Quit and consuming gate close are required before publication")
        guard let owner = originalLaunch else { throw Refusal.condition("original launch missing at publication") }
        try owner.acceptTerminal()
        _ = try remaining(1)
        print("MRK_MACOS_UI_ORIGINAL=outerRequest=1;completion=1;body=1;handoff=1;payloadIdentity=1;originalTerminated=1;gateFree=1;gateClosed=1;failureCleanup=0;caseDeadlineMet=1")
    }

    @MainActor private func retainPersistenceLifetimeForRestart(_ app: XCUIApplication,
                                                               fixture: LocalFixture) throws {
        try require(completedPersistenceLifetime == nil && normalQuitObserved && app.state == .notRunning,
                    "restart requires the first normal Quit and consuming gate close exactly once")
        guard let owner = originalLaunch, let gate = entryGateObservation else {
            throw Refusal.condition("first persistence lifetime custody missing")
        }
        try owner.acceptTerminal()
        try fixture.assertStoreUnchanged()
        completedPersistenceLifetime = CompletedPersistenceLifetime(owner: owner, gate: gate, normalQuit: normalQuitObserved)
        // Keep the first owner/gate/positive Quit facts above, using the original
        // case clock. This single transition cannot authorize a third launch.
        originalLaunch = nil
        entryGateObservation = nil
        normalQuitObserved = false
        _ = try remaining(1)
        print("MRK_MACOS_PERSISTENCE_LIFETIME=phase=1;outerRequest=1;completion=1;body=1;handoff=1;payloadIdentity=1;originalTerminated=1;gateFree=1;gateClosed=1;failureCleanup=0;caseDeadlineMet=1")
    }

    @MainActor private func checkOriginalOwners() throws {
        if let first = completedPersistenceLifetime {
            guard first.normalQuit else { throw caseClock?.fail("first normal Quit proof missing") ?? Refusal.condition("first normal Quit proof missing") }
            try first.owner.acceptTerminal()
        }
        if let owner = originalLaunch { try owner.healthy() }
    }

    @MainActor private func acceptPersistenceRestart() throws {
        try require(normalQuitObserved, "second normal Quit and consuming gate close are required before publication")
        guard let first = completedPersistenceLifetime, first.normalQuit, let owner = originalLaunch else {
            throw Refusal.condition("both persistence lifetime originals are required at publication")
        }
        try first.owner.acceptTerminal()
        try owner.acceptTerminal()
        _ = try remaining(1)
        print("MRK_MACOS_PERSISTENCE_LIFETIME=phase=2;outerRequest=1;completion=1;body=1;handoff=1;payloadIdentity=1;originalTerminated=1;gateFree=1;gateClosed=1;failureCleanup=0;caseDeadlineMet=1")
    }

    // Each lifetime retains one read-only original of the admitted permanent
    // gate. An EX observation is not proof of SH acquisition, process exit
    // status or all-worker finality. No gate creation, mutation or replacement.
    private final class GateObservation {
        static let path = "/Library/Application Support/MobileReleaseKit/maintenance-gate-v1"
        private var fd: Int32?
        private var entered = false
        private var original: StatFacts?
        func openOnce() throws {
            guard !entered else { throw Refusal.condition("gate observation repeated") }
            entered = true
            let opened = Darwin.open(Self.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard opened >= 0 else { throw Refusal.condition("permanent gate is unavailable") }
            fd = opened // Custody before any fallible observation.
            var info = stat()
            guard fstat(opened, &info) == 0 else { throw Refusal.condition("gate original stat failed") }
            original = StatFacts(info)
            try check()
        }
        private func check() throws {
            guard let fd, let original else { throw Refusal.condition("gate original missing") }
            var named = stat(), actual = stat()
            guard fstat(fd, &actual) == 0, lstat(Self.path, &named) == 0,
                  StatFacts(actual) == original, StatFacts(named) == original,
                  actual.st_mode == S_IFREG | 0o444, actual.st_uid == 0, actual.st_gid == 0,
                  actual.st_nlink == 1, actual.st_flags == 0, actual.st_size == 30,
                  fcntl(fd, F_GETFD) == FD_CLOEXEC else {
                throw Refusal.condition("gate original changed or protection refused")
            }
            var body = [UInt8](repeating: 0, count: 31)
            let count = body.withUnsafeMutableBytes { buffer in Darwin.pread(fd, buffer.baseAddress, buffer.count, 0) }
            guard count == 30, Array(body.prefix(30)) == Array("MRK-MACOS-MAINTENANCE-GATE-v1\n".utf8),
                  fstat(fd, &actual) == 0, StatFacts(actual) == original else {
                throw Refusal.condition("gate body changed")
            }
        }
        func probe(busy expected: Bool) throws {
            try check()
            guard let fd else { throw Refusal.condition("gate probe original missing") }
            let returned = flock(fd, LOCK_EX | LOCK_NB), error = errno
            let busy: Bool
            if returned == 0 {
                guard flock(fd, LOCK_UN) == 0 else { throw Refusal.condition("gate probe unlock failed") }
                busy = false
            } else {
                guard returned == -1 && error == EWOULDBLOCK else { throw Refusal.condition("gate probe failed") }
                busy = true
            }
            try check()
            guard busy == expected else { throw Refusal.condition("gate exclusion does not match original application lifetime") }
        }
        func closeOriginal() throws {
            if let opened = fd {
                fd = nil // Consume once, including on an unknown close result.
                guard Darwin.close(opened) == 0 else { throw Refusal.condition("gate observation close unknown") }
            }
        }
    }

    @MainActor private func require(_ value: Bool, _ reason: String,
                                    line: UInt = #line, check: RequireCheck = .condition,
                                    dashboard: (DashboardSnapshot, DashboardWaiter)? = nil) throws {
        guard value else {
            let originalFailureAbsent = caseClock?.firstFailure == nil
            let refusal = caseClock?.fail(reason) ?? Refusal.condition(reason)
            // A later caller must never be paired with an earlier latched reason.
            if packagedRequireDiagnosticActive && originalFailureAbsent && !packagedRequireDiagnosticEmitted
                && line >= 1 && line <= 65535 {
                packagedRequireDiagnosticEmitted = true
                print("MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=\(line);check=\(check.rawValue)")
                if let (sample, waiter) = dashboard, (1...4).contains(sample.ordinal), waiter != .completed {
                    // Immutable pre-wait DATA only; no native observation after failure.
                    print("MRK_MACOS_PACKAGED_DASHBOARD_FAILURE=v1;line=\(line);ordinal=\(sample.ordinal);waiter=\(waiter.rawValue);enabled=\(sample.enabled ? 1 : 0);hittable=\(sample.hittable ? 1 : 0);reason=\(sample.reason.rawValue);sample=pre-wait;nonAtomic=1")
                }
            }
            if engineeringRequireDiagnosticActive && originalFailureAbsent && !engineeringRequireDiagnosticEmitted
                && line >= 1 && line <= 65535 {
                engineeringRequireDiagnosticEmitted = true
                print("MRK_MACOS_ENGINEERING_REQUIRE_FAILURE=v1;line=\(line);check=\(check.rawValue)")
            }
            throw refusal
        }
        try checkOriginalOwners()
        if let clock = caseClock { _ = try clock.remaining(1, before: journeyDeadline) }
    }

    @MainActor private func unique(_ query: XCUIElementQuery, _ reason: String,
                                   line: UInt = #line) throws -> XCUIElement {
        try require(query.count == 1, reason, line: line, check: .singleton)
        return query.element(boundBy: 0)
    }

    @MainActor private func click(_ query: XCUIElementQuery, _ reason: String,
                                  line: UInt = #line) throws {
        let element = try unique(query, reason, line: line)
        try require(element.isEnabled && element.isHittable, reason, line: line, check: .actionable)
        element.click()
    }

    @MainActor private func dashboard(_ renderer: XCUIElement, diagnosticOrdinal: UInt8? = nil) throws {
        let heading = renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Good releases start here."))
        try require(heading.element(boundBy: 0).waitForExistence(timeout: try remaining(5)), "dashboard heading did not render")
        // Fixed dashboard query diagnostics only; observations are non-atomic.
        let observedCount = heading.count
        if observedCount != 1 {
            print("MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=initial;matches=\(min(observedCount, 5));exceedsFour=\(observedCount > 4 ? 1 : 0);nonAtomic=1")
            if observedCount > 1 && observedCount <= 4 {
                for property in ["identifier", "title", "label", "value", "placeholderValue"] {
                    let matches = heading.matching(NSPredicate(format: "%K == %@", property, "Good releases start here.")).count
                    print("MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=\(property);matches=\(min(matches, 5));exceedsFour=\(matches > 4 ? 1 : 0);nonAtomic=1")
                }
                let containing = heading.containing(.staticText, identifier: "Good releases start here.").count
                print("MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=containingSameStaticText;matches=\(min(containing, 5));exceedsFour=\(containing > 4 ? 1 : 0);nonAtomic=1")
            }
        }
        // Later diagnostic observations cannot repair the original singleton refusal.
        try require(observedCount == 1, "dashboard heading is ambiguous")
        // End fixed dashboard query diagnostics.
        let open = try unique(renderer.buttons.matching(identifier: "Open project folder"),
                              "ordinary first-party project control is missing or ambiguous")
        let snapshot: DashboardSnapshot?
        if packagedRequireDiagnosticActive, let ordinal = diagnosticOrdinal, (1...4).contains(ordinal) {
            // The added fixed observations use the same originals and case end.
            try checkOriginalOwners()
            _ = try remaining(5)
            let enabled = open.isEnabled
            let hittable = open.isHittable
            // Closed public literals only; never fetch or emit arbitrary AX text.
            // Sequential counts are non-atomic observations, not an internal cause.
            let reasons: [([String], DashboardReason)] = [
                ([
                    "Application capabilities are being loaded.",
                ], .loading),
                ([
                    "Application capabilities have not been loaded.",
                ], .notLoaded),
                ([
                    "The native desktop bridge is unavailable.",
                ], .bridgeUnavailable),
                ([
                    "Project selection is not available in the current desktop runtime profile.",
                ], .selectionUnavailable),
                ([
                    "Finish the original project selection first.",
                ], .selectionInProgress),
                ([
                    "The application is shutting down.",
                ], .shuttingDown),
                ([
                    "Offline-check ownership or finality is unverified. Keep the original status; conflicting work is disabled.",
                    "Saved offline checks hold the original intent or execution slot. Cancel or settle that original operation before conflicting work.",
                    "The original offline-check status is unverified. Check retained status before conflicting work.",
                ], .ownerOfflinePreflight),
                ([
                    "Android-build ownership or finality is unverified. Keep original Status and Cancel; conflicting work is disabled.",
                    "The original Android service action is active or unconfirmed. Keep its Status and Cancel; do not repeat registration.",
                    "The original Android source inspection or protected registration is active or unconfirmed. Keep its Status and Cancel; do not repeat copy.",
                    "An original source review is retained. Register that exact review or explicitly discard it before conflicting work.",
                    "The original Android tool picker or folder check is active or unconfirmed. Keep tool-selection Status and Cancel before conflicting work.",
                    "The original Android tool catalog is still reading, stopping or unconfirmed. Keep catalog Status and Cancel before conflicting work.",
                    "The Android build holds its original consent or execution slot. Cancel or settle that original operation before conflicting work.",
                    "The original Android-build status is unverified. Check retained Status before conflicting work.",
                ], .ownerAndroidBuild),
                ([
                    "iOS-archive ownership or finality is unverified. Keep original Status and Cancel; conflicting work is disabled.",
                    "The iOS archive holds its original consent or execution slot. Cancel or settle that original operation before conflicting work.",
                    "The original iOS-archive status is unverified. Check retained Status before conflicting work.",
                ], .ownerIOSArchive),
                ([
                    "Project-recovery ownership or finality is unverified. Keep the original status; conflicting work is disabled.",
                    "Project build-input recovery holds the original intent or execution slot. Cancel or settle that original operation before conflicting work.",
                    "The original project-recovery status is unverified. Check retained status before conflicting work.",
                ], .ownerProjectRecovery),
                ([
                    "The original GitHub preflight action is running or unverified. Read its local Status before starting another operation.",
                ], .ownerGitHubPreflight),
                ([
                    "The original protected release workflow action is running or unverified. Read its local Status before starting another operation.",
                ], .ownerGitHubRelease),
                ([
                    "The original project-path outcome or cleanup is unverified. Conflicting native operations remain blocked.",
                    "Finish the original project-path selection. Changing drafts or projects does not cancel it.",
                ], .ownerProjectPath),
                ([
                    "Saved-version edit ownership is unverified. Keep its original operation and do not retry.",
                    "A saved-version edit is still owned. Close or finish that original session before another operation.",
                    "This project needs separately authorized saved-version recovery. No other edit can clear that journal.",
                ], .ownerSavedVersionEdit),
                ([
                    "Original image ownership or cleanup is unverified. Observe that original operation; do not start a competing one.",
                    "An original image selection or local-copy review is retained. Finish or stop that operation first.",
                    "This project needs a separate image recovery inspection. Another edit cannot bypass its journal.",
                ], .ownerMetadataImages),
            ]
            var selected: DashboardReason?
            var ambiguous = false
            // Already-ready samples need no refusal queries; the real wait below is still required.
            if !enabled || !hittable {
                for (titles, reason) in reasons {
                    try checkOriginalOwners()
                    _ = try remaining(5)
                    let matches = renderer.staticTexts.matching(NSPredicate(
                        format: "identifier IN %@ OR label IN %@ OR title IN %@",
                        argumentArray: [titles, titles, titles])).count
                    if matches > 1 || (matches == 1 && selected != nil) {
                        ambiguous = true
                        break // No further diagnostic observation can repair ambiguity.
                    }
                    if matches == 1 { selected = reason }
                }
            }
            try checkOriginalOwners()
            _ = try remaining(5)
            snapshot = DashboardSnapshot(ordinal: ordinal, enabled: enabled, hittable: hittable,
                                         reason: ambiguous ? .ambiguous : selected ?? .otherOrUnobserved)
        } else { snapshot = nil }
        let ready = XCTNSPredicateExpectation(predicate: NSPredicate(format: "enabled == true AND hittable == true"), object: open)
        let returned = XCTWaiter.wait(for: [ready], timeout: try remaining(5))
        let readiness = snapshot.map { ($0, DashboardWaiter(returned)) }
        try require(returned == .completed, "ordinary project control is not usable", dashboard: readiness)
        try require(renderer.staticTexts.matching(identifier: "BROWSER PREVIEW — EXAMPLE DATA ONLY").count == 0,
                    "browser-preview data is not ordinary-app evidence")
    }

    @MainActor private func quitSheet(_ app: XCUIApplication, _ window: XCUIElement) throws -> XCUIElement {
        try require(window.sheets.count == 0, "an unrelated sheet is already present")
        let menuBar = try unique(app.menuBars, "application menu bar is missing or ambiguous")
        // The first Tauri submenu occupies the native application menu,
        // regardless of its source label. The fixed bundle names this app.
        try click(menuBar.menuBarItems.matching(identifier: "Mobile Release Kit"), "the application's native menu is unavailable")
        // Scoped to this application's opened menu bar, never a global keystroke.
        try click(menuBar.menuItems.matching(identifier: "Quit"), "the application menu has no unique Quit action")
        let query = window.sheets
        try require(query.element(boundBy: 0).waitForExistence(timeout: try remaining(5)), "normal Quit did not present its native sheet")
        let sheet = try unique(query, "normal Quit sheet is ambiguous")
        _ = try unique(sheet.staticTexts.matching(identifier: "Quit and discard unsaved drafts?"),
                       "unexpected confirmation sheet")
        try require(sheet.buttons.count == 2, "unexpected actions in the normal Quit sheet")
        _ = try unique(sheet.buttons.matching(identifier: "Cancel"), "normal Quit has no unique Cancel button")
        _ = try unique(sheet.buttons.matching(identifier: "Quit"), "normal Quit has no unique affirmative button")
        return sheet
    }

    private struct HostedAccount {
        let name: String
        let home: String
    }

    // getpwuid_r owns these C-string bytes in its caller-supplied buffer. Match
    // only the two fixed public values, including their terminator, in bounds.
    // Never inspect password/gecos or copy an unbounded native string.
    private func accountFieldMatches(_ value: UnsafeMutablePointer<CChar>?, _ expected: String,
                                     buffer: UnsafeMutableBufferPointer<CChar>) -> Bool {
        guard let value, let base = buffer.baseAddress else { return false }
        let address = UInt(bitPattern: value), start = UInt(bitPattern: base)
        let bytes = Array(expected.utf8)
        guard address >= start, address - start < UInt(buffer.count),
              UInt(bytes.count) < UInt(buffer.count) - (address - start) else { return false }
        let offset = Int(address - start)
        for (index, byte) in bytes.enumerated() {
            guard UInt8(bitPattern: buffer[offset + index]) == byte else { return false }
        }
        return buffer[offset + bytes.count] == 0
    }

    @MainActor private func hostedAccountRecord() throws -> HostedAccount {
        var record = passwd()
        var bytes = [CChar](repeating: 0, count: 64 * 1024)
        let uid = getuid(), gid = getgid()
        var lookupSucceeded = false, originalRecord = false
        var uidMatches = false, gidMatches = false, nameMatches = false, homeMatches = false
        bytes.withUnsafeMutableBufferPointer { buffer in
            withUnsafeMutablePointer(to: &record) { entry in
                var result: UnsafeMutablePointer<passwd>?
                let status = getpwuid_r(uid, entry, buffer.baseAddress!, buffer.count, &result)
                lookupSucceeded = status == 0
                originalRecord = lookupSucceeded && result == entry
                guard originalRecord else { return }
                uidMatches = entry.pointee.pw_uid == uid
                gidMatches = entry.pointee.pw_gid == gid
                nameMatches = accountFieldMatches(entry.pointee.pw_name, "runner", buffer: buffer)
                homeMatches = accountFieldMatches(entry.pointee.pw_dir, "/Users/runner", buffer: buffer)
            }
        }
        print("MRK_MACOS_UI_ACCOUNT_FACTS=lookupSucceeded=\(lookupSucceeded);originalRecord=\(originalRecord);uidMatches=\(uidMatches);gidMatches=\(gidMatches);nameMatches=\(nameMatches);homeMatches=\(homeMatches)")
        try require(lookupSucceeded && originalRecord && uidMatches && gidMatches && nameMatches && homeMatches,
                    "unsupported hosted account database record")
        // Only fixed values proved against the original UID record escape the
        // native buffer. Foundation's sandbox home is not account authority.
        return HostedAccount(name: "runner", home: "/Users/runner")
    }

    // Engineering main only: actual embedded UI and current-core reference data.
    // This never acquires the installed entry gate or any project/write permit.
    private enum LaunchProfile {
        case ordinary
        case engineeringMain(work: URL)
    }

    @MainActor private func engineeringWork() throws -> URL {
        #if !arch(arm64)
        throw Refusal.condition("engineering main fixture is ARM-only")
        #else
        _ = try admitHostedAccount() // The existing sameBuild SOURCE profile stays intact.
        let value = ProcessInfo.processInfo.environment["MRK_ENGINEERING_UI_WORK"] ?? ""
        let prefix = "/Users/runner/work/_temp/mrk-macos-engineering-ui."
        let suffix = value.hasPrefix(prefix) ? String(value.dropFirst(prefix.count)) : ""
        let alphabet = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        try require(suffix.utf8.count == 8 && suffix.unicodeScalars.allSatisfy(alphabet.contains),
                    "engineering main work binding is not the fixed fresh family")
        let work = URL(fileURLWithPath: value, isDirectory: true)
        try require(work.path == value && work.standardizedFileURL.path == value,
                    "engineering main work binding is not canonical")
        return work
        #endif
    }

    @MainActor private func launchEngineeringMain(work: URL) throws -> XCUIApplication {
        guard let clock = caseClock else { throw Refusal.condition("original engineering case clock missing") }
        try require(originalLaunch == nil && entryGateObservation == nil && completedPersistenceLifetime == nil && !normalQuitObserved,
                    "engineering launch requires empty original custody")
        let url = work.appendingPathComponent("Mobile Release Kit.app", isDirectory: true)
        let monitor = XCUIApplication(url: url)
        // Read-only occupancy checks confer no cleanup or adoption authority.
        try require(monitor.state == .notRunning
                    && NSRunningApplication.runningApplications(withBundleIdentifier: "dev.mobile-release-kit.engineering-ui").isEmpty
                    && !NSWorkspace.shared.runningApplications.contains(where: { $0.bundleURL?.path == url.path }),
                    "occupied engineering fixture must not be launched, adopted or terminated")
        let owner = OrdinaryLaunch(clock: clock, profile: .engineeringMain(work: work))
        originalLaunch = owner // SAME first-reference owner before the one fallible request.
        try owner.requestAndAwait()
        try owner.healthy()
        return monitor // Monitoring/clicks only; it never creates or replaces the original.
    }

    @MainActor private func engineeringDashboard(_ renderer: XCUIElement) throws {
        let heading = renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Good releases start here."))
        _ = try waitElement(heading, in: renderer)
        _ = try unique(renderer.staticTexts.matching(identifier: "Select a project to see its configuration and discover static build hints."),
                       "engineering smoke unexpectedly selected a project")
        let open = try unique(renderer.buttons.matching(identifier: "Open project folder"), "engineering dashboard project control differs")
        let choose = try unique(renderer.buttons.matching(identifier: "Choose a project"), "engineering dashboard selection control differs")
        try require(!open.isEnabled && !choose.isEnabled,
                    "engineering smoke must not enable Mac development project or writer admission")
        try engineeringNoFallback(renderer)
    }

    @MainActor private func engineeringNoFallback(_ renderer: XCUIElement) throws {
        for message in ["BROWSER PREVIEW — EXAMPLE DATA ONLY", "Loading desktop capabilities and the core field catalogue…",
                        "The native service is unavailable", "The field catalogue could not be loaded",
                        "The guided asset catalogue is unavailable", "The engine is disabled", "Bundled engine unavailable"] {
            try require(renderer.staticTexts.matching(identifier: message).count == 0,
                        "engineering UI has a loading, unavailable or example substitute")
        }
    }

    @MainActor
    func testEngineeringMainCatalogueAndQuit() throws {
        engineeringRequireDiagnosticActive = true
        defer { engineeringRequireDiagnosticActive = false }
        continueAfterFailure = false
        executionTimeAllowance = 60
        try beginCase(seconds: 60) // Includes original host/source/input admission.
        let work = try engineeringWork()
        let app = try launchEngineeringMain(work: work)
        try require(app.wait(for: .runningForeground, timeout: try remaining(5)), "engineering main did not enter foreground")
        try require(app.windows.element(boundBy: 0).waitForExistence(timeout: try remaining(5)), "engineering main window missing")
        let window = try unique(app.windows, "engineering main window ambiguous")
        try require(window.isHittable, "engineering main window unusable")
        let renderers = window.webViews
        let initial = renderers.count
        try require(initial <= 1, "engineering first-party renderer ambiguous")
        if initial == 0 {
            try require(renderers.element(boundBy: 0).waitForExistence(timeout: try remaining(5)), "engineering renderer missing")
        }
        let renderer = try unique(renderers, "engineering renderer missing or ambiguous")
        // Wait on actual current-core guide data below, not a static UI heading.
        // Initial loading may settle; no retry/second app or fallback is allowed.
        _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Good releases start here.")), in: renderer)
        try click(renderer.buttons.matching(identifier: "Credentials"), "engineering Credentials navigation unavailable")
        _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Private by design.")), in: renderer)
        let guide = try waitElement(named(renderer, "Credential and signing asset guides"), in: renderer,
                                   failures: ["The native service is unavailable", "The field catalogue could not be loaded"])
        _ = try unique(controls(guide, [.button], label: "Android upload keystore", prefix: true),
                       "actual core Android guide is missing or repeated")
        let apple = try unique(controls(guide, [.button], label: "Apple Distribution identity", prefix: true),
                               "actual core Apple guide is missing or repeated")
        try reveal(apple, in: renderer)
        try require(apple.isEnabled && apple.isHittable, "actual core guide selection unavailable")
        apple.click() // Reference-only selection: no credential import or operation.
        _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Original Distribution P12")), in: renderer)
        _ = try unique(renderer.staticTexts.matching(identifier: "Reference guide · not a result"),
                       "guide was not explicitly reference-only")
        try engineeringNoFallback(renderer)
        try require(window.sheets.count == 0, "reference navigation opened an unexpected native operation")

        let first = try quitSheet(app, window)
        try click(first.buttons.matching(identifier: "Cancel"), "engineering normal Quit Cancel unavailable")
        try waitGone(first)
        try require(app.state == .runningForeground && window.exists && window.isHittable,
                    "engineering Quit Cancel did not retain the same usable window")
        try click(renderer.buttons.matching(identifier: "Dashboard"), "engineering post-Cancel navigation unavailable")
        try engineeringDashboard(renderer)
        let second = try quitSheet(app, window)
        try click(second.buttons.matching(identifier: "Quit"), "engineering normal Quit confirmation unavailable")
        guard let clock = caseClock, let owner = originalLaunch, entryGateObservation == nil else {
            throw Refusal.condition("engineering original custody changed")
        }
        let end = try clock.end(within: 10)
        try require(app.wait(for: .notRunning, timeout: try clock.remaining(10, before: end)), "engineering normal Quit did not stop UI")
        try owner.observeNormalTermination(until: end) // SAME absolute end and original.
        try require(app.state == .notRunning, "engineering UI changed after original termination")
        try owner.acceptTerminal()
        normalQuitObserved = true // Existing teardown still rechecks this SAME original.
        _ = try remaining(1)
        // Not final until original XCTest/xcodebuild, products/input POST, summary
        // and the existing runner's consuming closes/returned status also pass.
        print("MRK_MACOS_ENGINEERING_MAIN_UI=mainRequest=1;completion=1;body=1;handoff=1;mainIdentity=1;catalogueGuide=1;projectSelected=0;editCapability=unavailable;originalTerminated=1;failureCleanup=0;caseDeadlineMet=1;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }
    // End engineering main fixture; ordinary installed cases below are unchanged.

    private enum SourceProfile { case sameBuild, packagedEntry }

    @MainActor private func admitHostedAccount(_ profile: SourceProfile = .sameBuild) throws -> HostedAccount {
        let context = ProcessInfo.processInfo.environment
        #if arch(arm64)
        let hostedJob = "github-hosted-macos26-arm64"
        #elseif arch(x86_64)
        let hostedJob = "github-hosted-macos26-x86_64"
        #endif
        try require(context["MRK_NORMAL_UI_HOSTED_JOB"] == hostedJob,
                    "this scenario is not admitted on a shared or personal desktop")
        let nonroot = getuid() != 0
        let sameUid = getuid() == geteuid()
        let sameGid = getgid() == getegid()
        try require(nonroot && sameUid && sameGid,
                    "the ordinary application must run as the original nonroot account")
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let runnerName = NSUserName() == "runner"
        let fixedHome = NSHomeDirectory() == "/Users/runner"
        // Closed diagnostics only: never raw account/home/environment contents.
        print("MRK_MACOS_UI_HOST_FACTS=os=\(version.majorVersion).\(version.minorVersion).\(version.patchVersion);nonroot=\(nonroot);sameUid=\(sameUid);sameGid=\(sameGid);runnerName=\(runnerName);fixedHome=\(fixedHome)")
        let envHome = context["HOME"] == "/Users/runner"
        let envUser = context["USER"] == "runner"
        let envLogname = context["LOGNAME"] == "runner"
        let fixedHomePresent = context["CFFIXED_USER_HOME"] != nil
        let versionCompatPresent = context["SYSTEM_VERSION_COMPAT"] != nil
        print("MRK_MACOS_UI_HOST_ENV_FACTS=homeIsRunner=\(envHome);userIsRunner=\(envUser);lognameIsRunner=\(envLogname);fixedHomePresent=\(fixedHomePresent);versionCompatPresent=\(versionCompatPresent)")
        try require(version.majorVersion == 26, "unsupported hosted OS major")
        try require(runnerName, "unsupported hosted Foundation account name")
        let account = try hostedAccountRecord()
        let applicationSource = context["MRK_NORMAL_UI_APPLICATION_SOURCE"] ?? ""
        let harnessSource = context["MRK_NORMAL_UI_HARNESS_SOURCE"] ?? ""
        let hexadecimal = CharacterSet(charactersIn: "0123456789abcdef")
        try require(applicationSource.utf8.count == 40 && applicationSource.unicodeScalars.allSatisfy(hexadecimal.contains)
                    && harnessSource.utf8.count == 40 && harnessSource.unicodeScalars.allSatisfy(hexadecimal.contains),
                    "exact application and harness source bindings are required")
        switch profile {
        case .sameBuild:
            try require(applicationSource == harnessSource,
                        "this same-build scenario needs exact application and harness source bindings")
        case .packagedEntry:
            try require(applicationSource == "53850a9fd94768a2521f2634db6121550dbdd71c" && harnessSource != applicationSource
                        && context["MRK_NORMAL_UI_ARTIFACT_ID"] == "11281078057"
                        && context["MRK_NORMAL_UI_ARCHIVE_BYTES"] == "50972943"
                        && context["MRK_NORMAL_UI_ARCHIVE_SHA256"] == "dfb46e23f7b397facc1a9b69b77d1440960fb846bedc90a573f2410b230255d0"
                        && context["MRK_NORMAL_UI_PACKAGE_BYTES"] == "50964188"
                        && context["MRK_NORMAL_UI_PACKAGE_SHA256"] == "618c873f0b841b54faceae9e5ad1ca073a94215a1a53cee0bf28c3aa17361119",
                        "only the separately selected fixed packaged-entry case may reuse this package")
        }
        return account
    }

    @MainActor
    func testLaunchCancelAndQuit() throws {
        try launchCancelAndQuit(profile: .sameBuild)
    }

    @MainActor
    func testPackagedEntryLaunchCancelAndQuit() throws {
        try launchCancelAndQuit(profile: .packagedEntry)
    }

    @MainActor private func launchCancelAndQuit(profile: SourceProfile) throws {
        packagedRequireDiagnosticActive = true
        defer { packagedRequireDiagnosticActive = false }
        continueAfterFailure = false
        // XCTest's whole-minute allowance remains exactly sixty seconds.
        executionTimeAllowance = 60
        try beginCase(seconds: 60) // Before any in-case account or installation admission.
        _ = try admittedJourneyApplication(profile: profile)
        let app = try launchOrdinaryApplication()
        guard let gate = entryGateObservation else { throw Refusal.condition("original gate observation missing") }
        try require(app.wait(for: .runningForeground, timeout: try remaining(5)), "ordinary app did not enter the foreground")
        try require(app.windows.element(boundBy: 0).waitForExistence(timeout: try remaining(5)), "ordinary app has no visible main window")
        let window = try unique(app.windows, "ordinary main window is ambiguous")
        try require(window.isHittable, "ordinary main window is not usable")
        // Bounded initial renderer readiness; observed ambiguity remains terminal.
        let rendererQuery = window.webViews
        let rendererCount = rendererQuery.count
        if rendererCount != 1 {
            print("MRK_MACOS_NORMAL_RENDERER_QUERY=observation=initial;matches=\(min(rendererCount, 5));exceedsFour=\(rendererCount > 4 ? 1 : 0);nonAtomic=1")
        }
        try require(rendererCount <= 1, "ordinary first-party renderer is ambiguous")
        var observedReadyCount = rendererCount
        if rendererCount == 0 {
            try require(rendererQuery.element(boundBy: 0).waitForExistence(timeout: try remaining(5)),
                        "ordinary first-party renderer did not appear")
            observedReadyCount = rendererQuery.count
        }
        try require(observedReadyCount == 1, "ordinary first-party renderer is missing or ambiguous")
        let renderer = rendererQuery.element(boundBy: 0)
        // End bounded initial renderer readiness.
        try dashboard(renderer, diagnosticOrdinal: 1)
        try gate.probe(busy: true)
        // Exercise the real same-window native picker without selecting a
        // project or creating a document/Store operation.
        try click(renderer.buttons.matching(identifier: "Open project folder"), "native project picker is unavailable")
        let picker = try nativeSheet(window, title: "Choose a mobile project folder")
        try gate.probe(busy: true)
        try click(picker.buttons.matching(identifier: "Cancel"), "native project picker Cancel is unavailable")
        let pickerDismissed = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: picker)
        try require(XCTWaiter.wait(for: [pickerDismissed], timeout: try remaining(5)) == .completed, "native picker Cancel did not settle")
        try dashboard(renderer, diagnosticOrdinal: 2)

        let first = try quitSheet(app, window)
        try click(first.buttons.matching(identifier: "Cancel"), "normal Quit Cancel is unavailable")
        let dismissed = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: first)
        try require(XCTWaiter.wait(for: [dismissed], timeout: try remaining(5)) == .completed, "Cancel did not dismiss the normal Quit sheet")
        try require(app.state == .runningForeground && window.exists, "Cancel did not preserve the running application")
        try dashboard(renderer, diagnosticOrdinal: 3)
        // Prove renderer responsiveness after Cancel without selecting a project,
        // changing configuration or invoking a Store.
        try click(renderer.buttons.matching(identifier: "Project settings"), "post-Cancel navigation is unavailable")
        try require(renderer.staticTexts.matching(identifier: "A little clarity before the next release.")
                    .element(boundBy: 0).waitForExistence(timeout: try remaining(5)), "post-Cancel settings navigation failed")
        try click(renderer.buttons.matching(identifier: "Dashboard"), "post-Cancel Dashboard navigation is unavailable")
        try dashboard(renderer, diagnosticOrdinal: 4)

        let second = try quitSheet(app, window)
        try click(second.buttons.matching(identifier: "Quit"), "normal affirmative Quit is unavailable")
        try completeNormalQuit(app)
        try acceptFinalScenario()
        print("MRK_MACOS_ENTRY_UI=ordinary-entry-payload-picker-quit-and-gate-exclusion-observed;directPayloadPreMain=unqualified;allWorkerFinality=unavailable;maintenance=unavailable")
        // Not final until the original XCTest/xcodebuild result also succeeds.
        print("MRK_MACOS_NORMAL_UI=launch-render-cancel-navigation-quit-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }


    // Finite synthetic files only. No existing project, .git, credential, tool
    // input or script is copied from a user. The separate persistence profile
    // contains inert signature-less envelopes, never usable signing material.
    // Retain the small fixture for job retirement:
    // XCTest notRunning does not prove all-worker finality for deletion.
    private struct FixtureSpec: Decodable {
        let schemaVersion: Int
        let files: [String: String]
        let stages: [String: [String: String]]
        let templateDataSHA256: String?
    }
    private struct StatFacts: Equatable {
        let device: dev_t
        let inode: ino_t
        let mode: mode_t
        let uid: uid_t
        let gid: gid_t
        let links: nlink_t
        let flags: UInt32
        let bytes: off_t
        let modifiedSeconds: time_t
        let modifiedNanoseconds: Int
        let changedSeconds: time_t
        let changedNanoseconds: Int
        init(_ s: stat) {
            device = s.st_dev; inode = s.st_ino; mode = s.st_mode
            uid = s.st_uid; gid = s.st_gid; links = s.st_nlink; flags = s.st_flags; bytes = s.st_size
            modifiedSeconds = s.st_mtimespec.tv_sec; modifiedNanoseconds = s.st_mtimespec.tv_nsec
            changedSeconds = s.st_ctimespec.tv_sec; changedNanoseconds = s.st_ctimespec.tv_nsec
        }
        func sameDirectory(_ other: StatFacts) -> Bool {
            // Legitimate child creation changes directory timestamps/link count.
            device == other.device && inode == other.inode && mode == other.mode
                && uid == other.uid && gid == other.gid && flags == other.flags
        }
    }
    private final class LocalFixture {
        enum Profile: Equatable { case projectEdits, projectFields, persistentCredentials, workflowRefusal }
        enum StoreChange { case initialize, saveP12, saveProfile, replaceP12, deleteProfile }
        static let config = "project/release/mobile-release.json"
        static let version = "project/release/version.properties"
        static let title = "project/release/store/android/fr-FR/title.txt"
        static let callerNames = ["preflight", "candidate", "external-testing", "production-submit"]
        static let controls = [
            ".mobile-release-init-prepare", ".mobile-release-init", ".mobile-release-init-cleanup",
            ".mobile-release-metadata-text-prepare", ".mobile-release-metadata-text", ".mobile-release-metadata-text-cleanup",
            ".mobile-release-version-prepare", ".mobile-release-version", ".mobile-release-version-cleanup",
            ".mobile-release-metadata-images-prepare", ".mobile-release-metadata-images", ".mobile-release-metadata-images-cleanup"
        ]
        static var callers: [String] { callerNames.map { "project/.github/workflows/mobile-\($0).yml" } }
        static var imageTargets: [String] {
            ["01", "02"].map { "project/release/store/android/fr-FR/images/phoneScreenshots/\($0).png" }
        }
        static var originals: Set<String> {
            var result: Set<String> = [config, version, "project/.gitignore",
                "project/README-user.txt", "project/.github/workflows/keep-user.yml", "sources/01.png", "sources/02.png"]
            for locale in ["en-US", "fr-FR"] {
                for name in ["title.txt", "short_description.txt", "full_description.txt"] {
                    result.insert("project/release/store/android/\(locale)/\(name)")
                }
            }
            return result
        }
        // Extra selection-only DATA belongs only to the ordinary project-field case.
        // The same originals/current/ancestor inventory owns and verifies every leaf.
        static let projectFieldAdditions: [String: Data] = [
            "project/inputs/VERSION": Data("VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n".utf8),
            "project/ios/Example.xcodeproj/project.pbxproj": Data("// Selection-only fixture; not an Xcode build.\n".utf8),
            "project/ios/Example.xcworkspace/contents.xcworkspacedata": Data("<Workspace version=\"1.0\"></Workspace>\n".utf8),
            "project/metadata/README.txt": Data("Selection-only metadata folder; no Store content.\n".utf8)
        ]
        // Inert folder-selection DATA only, separate from the unchanged four
        // project-field additions. No SDK/JDK/Gradle executable or supplier data.
        static let androidSourceAdditions: [String: Data] = [
            "sources/tool-jdk.jdk/README.txt": Data("MRK_NORMAL_ANDROID_SOURCE_SELECTION_ONLY\n".utf8),
            "sources/tool-sdk/README.txt": Data("MRK_NORMAL_ANDROID_SOURCE_SELECTION_ONLY\n".utf8),
            "sources/tool-gradle/README.txt": Data("MRK_NORMAL_ANDROID_SOURCE_SELECTION_ONLY\n".utf8),
            "sources/tool-jdk-replacement.jdk/README.txt": Data("MRK_NORMAL_ANDROID_SOURCE_SELECTION_ONLY\n".utf8),
            "sources/tool-refused/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/README.txt": Data("MRK_NORMAL_ANDROID_SOURCE_SELECTION_ONLY\n".utf8)
        ]
        static let androidRefusedDirectory = "sources/tool-refused/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d"
        static let persistenceOriginals: Set<String> = [config, version, "project/.gitignore", "project/README-user.txt",
            "project/ios/MRKObserved.xcodeproj/project.pbxproj",
            "project/ios/MRKObserved.xcodeproj/xcshareddata/xcschemes/MRKObserved.xcscheme",
            "project/ios/MRKObserved.xcodeproj/project.xcworkspace/contents.xcworkspacedata",
            "project/ios/MRKObserved/main.m", "project/ios/MRKObserved/Info.plist",
            "sources/synthetic.p12", "sources/synthetic.mobileprovision"]
        static let applicationName = "dev.mobile-release-kit.desktop"
        static let storeControls: [String: Int] = ["vault-lock": 0, "initialization-reservation": 48, "vault-header": 104]
        private struct Directory {
            let fd: Int32
            let parent: Int32?
            let name: String
            let facts: StatFacts
        }
        private struct File { let bytes: Data; let facts: StatFacts }
        private var descriptors: [Int32] = []
        private var directories: [String: Directory] = [:]
        private var anchors: [Directory] = []
        private var originals: [String: Data] = [:]
        private var changes: [String: [String: Data]] = [:]
        private var current: [String: File] = [:]
        private var acceptedStages: Set<String> = []
        private var closeErrors: [String] = []
        private var applicationSupport: Directory?
        private var applicationDirectory: Directory?
        private var vaultDirectory: Directory?
        private var storeCurrent: [String: File] = [:]
        private var p12Record: String?
        private var profileRecord: String?
        private var replacedP12 = false
        private var deletedProfile = false
        private(set) var rootPath = ""
        var projectPath: String { rootPath + "/project" }
        var sourcesPath: String { rootPath + "/sources" }

        private static func need(_ value: Bool, _ reason: String) throws {
            guard value else { throw Refusal.condition("fixture: " + reason) }
        }
        private static func facts(_ fd: Int32) throws -> StatFacts {
            var s = stat()
            try need(fstat(fd, &s) == 0, "original descriptor stat failed")
            return StatFacts(s)
        }
        private static func named(_ parent: Int32, _ name: String) throws -> StatFacts {
            var s = stat()
            try need(fstatat(parent, name, &s, AT_SYMLINK_NOFOLLOW) == 0, "named stat failed: " + name)
            return StatFacts(s)
        }
        private func adoptDirectory(_ fd: Int32, parent: Int32?, name: String) throws -> Directory {
            try Self.need(fd >= 0, "directory open failed")
            descriptors.append(fd) // Adopt before the first fallible observation.
            let value = try Self.facts(fd)
            try Self.need(value.mode & mode_t(S_IFMT) == mode_t(S_IFDIR), "not an original directory")
            if let parent {
                try Self.need(value == Self.named(parent, name), "directory entry changed")
            }
            return Directory(fd: fd, parent: parent, name: name, facts: value)
        }
        private func checkDirectory(_ value: Directory) throws {
            let actual = try Self.facts(value.fd)
            try Self.need(value.facts.sameDirectory(actual), "directory original changed")
            if let parent = value.parent {
                try Self.need(actual.sameDirectory(Self.named(parent, value.name)), "directory binding changed")
            }
        }
        private static func ancestors(_ paths: Set<String>) -> [String] {
            var values: Set<String> = [""]
            for path in paths {
                var parts = path.split(separator: "/").map(String.init)
                while parts.count > 1 {
                    parts.removeLast(); values.insert(parts.joined(separator: "/"))
                }
            }
            return values.sorted {
                let first = $0.split(separator: "/").count, second = $1.split(separator: "/").count
                return first == second ? $0 < $1 : first < second
            }
        }
        private static func parts(_ path: String) -> (String, String) {
            let items = path.split(separator: "/").map(String.init)
            return (items.dropLast().joined(separator: "/"), items.last!)
        }
        private func read(_ path: String) throws -> File {
            try Self.need(closeErrors.isEmpty, "an earlier consuming close failed")
            let (parent, name) = Self.parts(path)
            guard let original = directories[parent] else { throw Refusal.condition("fixture: missing fixed parent") }
            return try readLeaf(original, name: name)
        }
        private func readLeaf(_ original: Directory, name: String, privateOnly: Bool = false) throws -> File {
            try Self.need(closeErrors.isEmpty, "an earlier consuming close failed")
            try checkDirectory(original)
            let fd = openat(original.fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            try Self.need(fd >= 0, "fixed leaf open failed")
            defer { if Darwin.close(fd) != 0 { closeErrors.append("fixed-leaf-close") } }
            let before = try Self.facts(fd)
            try Self.need(before.mode & mode_t(S_IFMT) == mode_t(S_IFREG) && before.links == 1
                && before.uid == getuid() && before.gid == getgid() && before.bytes >= 0 && before.bytes <= 32 * 1024
                && before.mode & 0o7022 == 0
                && (!privateOnly || before.mode & 0o7777 == 0o600 && before.flags == 0
                    && before.device == original.facts.device), "leaf shape/mode/limit")
            var bytes = Data(), buffer = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
                try Self.need(count >= 0, "fixed leaf read failed")
                if count == 0 { break }
                try Self.need(bytes.count + count <= 32 * 1024, "fixed leaf read limit")
                bytes.append(contentsOf: buffer.prefix(count))
            }
            try Self.need(bytes.count == before.bytes && before == Self.facts(fd)
                && before == Self.named(original.fd, name), "fixed leaf changed during observation")
            return File(bytes: bytes, facts: before)
        }
        private func children(_ directory: Directory) throws -> Set<String> {
            try checkDirectory(directory)
            let before = try Self.facts(directory.fd)
            // A fresh owned enumeration FD avoids changing the original's offset.
            let fd = openat(directory.fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            try Self.need(fd >= 0, "owned roster open failed")
            guard let stream = fdopendir(fd) else {
                if Darwin.close(fd) != 0 { closeErrors.append("roster-open-close") }
                throw Refusal.condition("fixture: owned roster conversion failed")
            }
            defer { if closedir(stream) != 0 { closeErrors.append("roster-close") } }
            var result: Set<String> = []
            while true {
                errno = 0
                guard let entry = readdir(stream) else {
                    try Self.need(errno == 0, "owned roster read failed"); break
                }
                let name = withUnsafePointer(to: &entry.pointee.d_name) {
                    $0.withMemoryRebound(to: CChar.self, capacity: Int(NAME_MAX) + 1) { String(cString: $0) }
                }
                if name == "." || name == ".." { continue }
                try Self.need(result.count < 64 && !result.contains(name), "owned roster limit/duplicate")
                result.insert(name)
            }
            try Self.need(before == Self.facts(directory.fd), "owned roster changed during enumeration")
            try checkDirectory(directory)
            return result
        }
        private func checkRoster() throws {
            for value in anchors { try checkDirectory(value) }
            let leafPaths = Set(current.keys)
            let expectedDirectories = Set(Self.ancestors(leafPaths))
            try Self.need(Set(directories.keys) == expectedDirectories, "unexpected registered directory")
            for path in expectedDirectories.sorted() {
                guard let directory = directories[path] else { throw Refusal.condition("fixture: directory absent") }
                let prefix = path.isEmpty ? "" : path + "/"
                let expected = Set(leafPaths.union(expectedDirectories).compactMap { item -> String? in
                    guard item.hasPrefix(prefix), item != path else { return nil }
                    let suffix = String(item.dropFirst(prefix.count))
                    return suffix.contains("/") ? nil : suffix
                })
                try Self.need(try children(directory) == expected, "unexpected owned output under " + path)
            }
            let project = directories["project"]!
            for name in Self.controls + [".git"] {
                var s = stat()
                let returned = fstatat(project.fd, name, &s, AT_SYMLINK_NOFOLLOW)
                let error = errno
                try Self.need(returned == -1 && error == ENOENT, "unexpected project control: " + name)
            }
            try Self.need(closeErrors.isEmpty, "a consuming file/roster close failed")
        }
        func prepare(_ profile: Profile = .projectEdits) throws {
            try Self.need(rootPath.isEmpty && current.isEmpty, "fixture preparation was repeated")
            let projectData = profile != .persistentCredentials
            let resourceName = projectData ? "normal-project-v1" : "normal-persistence-v1"
            guard let url = Bundle(for: NormalAppUITests.self).url(forResource: resourceName, withExtension: "json") else {
                throw Refusal.condition("fixture: bundled fixed DATA absent")
            }
            let resource = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            try Self.need(resource >= 0, "bundled DATA open failed")
            let data: Data
            do {
                let before = try Self.facts(resource)
                try Self.need(before.mode & mode_t(S_IFMT) == mode_t(S_IFREG) && before.links == 1
                    && before.bytes > 0 && before.bytes <= 64 * 1024, "bundled DATA shape/limit")
                var body = Data(), buffer = [UInt8](repeating: 0, count: 4096)
                while true {
                    let count = buffer.withUnsafeMutableBytes { Darwin.read(resource, $0.baseAddress!, $0.count) }
                    try Self.need(count >= 0, "bundled DATA read failed")
                    if count == 0 { break }
                    try Self.need(body.count + count <= 64 * 1024, "bundled DATA read limit")
                    body.append(contentsOf: buffer.prefix(count))
                }
                try Self.need(body.count == before.bytes && before == Self.facts(resource), "bundled DATA changed")
                data = body
            } catch {
                if Darwin.close(resource) != 0 { closeErrors.append("resource-close") }
                throw error
            }
            if Darwin.close(resource) != 0 { closeErrors.append("resource-close") }
            try Self.need(closeErrors.isEmpty, "bundled DATA close failed")
            let spec = try JSONDecoder().decode(FixtureSpec.self, from: data)
            let stagePaths: [String: Set<String>] = projectData ? [
                "config": [Self.config, "project/.gitignore"], "workflows": Set(Self.callers),
                "text": [Self.title], "version": [Self.version], "images": Set(Self.imageTargets)
            ] : [:]
            let expectedOriginals = projectData ? Self.originals : Self.persistenceOriginals
            try Self.need(spec.schemaVersion == 1 && Set(spec.files.keys) == expectedOriginals
                && Set(spec.stages.keys) == Set(stagePaths.keys)
                && (projectData ? spec.templateDataSHA256?.count == 64 : spec.templateDataSHA256 == nil),
                "fixed DATA inventory mismatch")
            func decode(_ values: [String: String]) throws -> [String: Data] {
                var decoded: [String: Data] = [:]
                for (path, encoded) in values {
                    guard let bytes = Data(base64Encoded: encoded), bytes.count <= 32 * 1024 else {
                        throw Refusal.condition("fixture: bounded payload encoding")
                    }
                    decoded[path] = bytes
                }
                return decoded
            }
            originals = try decode(spec.files)
            if profile == .projectFields {
                try Self.need(Set(originals.keys).isDisjoint(with: Self.projectFieldAdditions.keys),
                              "fixed project-field DATA collides with an original")
                for (path, bytes) in Self.projectFieldAdditions { originals[path] = bytes }
                try Self.need(Self.androidSourceAdditions.count == 5
                    && Self.androidSourceAdditions.values.allSatisfy({
                        $0.count == 41 && $0 == Data("MRK_NORMAL_ANDROID_SOURCE_SELECTION_ONLY\n".utf8)
                    }), "fixed Android source DATA count/bytes differ")
                try Self.need(Set(originals.keys).isDisjoint(with: Self.androidSourceAdditions.keys),
                              "fixed Android source DATA collides with an original")
                for (path, bytes) in Self.androidSourceAdditions { originals[path] = bytes }
                // Before creating anything: 22 leaves, 143 retained directory
                // originals plus 3 anchors = 146 fixture FDs, 147 with one
                // temporary read/enumeration FD. The case's original gate is
                // separate; this is a census, never an OS-headroom claim.
                try Self.need(originals.count == 22 && Self.ancestors(Set(originals.keys)).count == 143,
                              "fixed Android source fixture census differs")
                let refusedPath = "/private/tmp/mrk-normal-project-XXXXXX/" + Self.androidRefusedDirectory
                try Self.need(Self.androidRefusedDirectory.split(separator: "/").count == 125
                    && refusedPath.split(separator: "/").count == 128 && refusedPath.utf8.count == 305
                    && Self.androidSourceAdditions[Self.androidRefusedDirectory + "/README.txt"]
                        == Data("MRK_NORMAL_ANDROID_SOURCE_SELECTION_ONLY\n".utf8),
                    "fixed Android source refusal path differs")
            }
            for (stage, paths) in stagePaths {
                guard let values = spec.stages[stage], Set(values.keys) == paths else {
                    throw Refusal.condition("fixture: stage path inventory mismatch")
                }
                changes[stage] = try decode(values)
            }
            if profile == .workflowRefusal {
                // Derive both managed originals only from unchanged bundled DATA,
                // before any filesystem creation. No rendered/current bytes are trusted.
                let preflight = "project/.github/workflows/mobile-preflight.yml"
                let candidate = "project/.github/workflows/mobile-candidate.yml"
                guard let canonical = changes["workflows"]?[preflight],
                      let candidateTemplate = changes["workflows"]?[candidate] else {
                    throw Refusal.condition("fixture: fixed workflow stage DATA absent")
                }
                let suffix = Data("# MRK synthetic user customization; preserve exactly.\n".utf8)
                func digest(_ bytes: Data) -> String {
                    SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
                }
                let customized = candidateTemplate + suffix
                try Self.need(originals[preflight] == nil && originals[candidate] == nil
                    && canonical.count == 1490
                    && digest(canonical) == "9abe5b0e3eb048c4256b781cc4f62bd2247631a876cf704d0a384b4b03eda1fb"
                    && suffix.count == 54
                    && digest(suffix) == "86aecf8c848119fbfd7f097fb9d942cab6ea29ea5abe284004b074b855ee655c"
                    && customized.count == 2368
                    && digest(customized) == "cb50a58a62167a9e25da9eeb42a2c2d448f47445515e9fc291d3a23543762933",
                    "fixed managed workflow originals differ")
                originals[preflight] = canonical
                originals[candidate] = customized
                let originalBytes = originals.values.reduce(0) { $0 + $1.count }
                let stageBytes = changes.values.flatMap { $0.values }.reduce(0) { $0 + $1.count }
                // 10 fixture directories + 3 anchors = 13 retained FDs; 14
                // with one transient leaf/roster reader. The app gate is separate.
                try Self.need(originals.count == 15 && Self.ancestors(Set(originals.keys)).count == 10
                    && originalBytes == 5232 && stageBytes == 12137 && originalBytes + stageBytes == 17369
                    && originals.values.allSatisfy { $0.count <= 32 * 1024 },
                    "fixed managed workflow fixture census differs")
            }
            try Self.need(originals.values.reduce(0) { $0 + $1.count }
                + changes.values.flatMap { $0.values }.reduce(0) { $0 + $1.count } <= 256 * 1024,
                "whole fixture DATA limit")
            let slash = try adoptDirectory(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: nil, name: "/")
            anchors.append(slash)
            let privateDirectory = try adoptDirectory(openat(slash.fd, "private", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                parent: slash.fd, name: "private")
            anchors.append(privateDirectory)
            let temporary = try adoptDirectory(openat(privateDirectory.fd, "tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                parent: privateDirectory.fd, name: "tmp")
            anchors.append(temporary)
            var template = Array("/private/tmp/mrk-normal-project-XXXXXX".utf8CString)
            let made = template.withUnsafeMutableBufferPointer { mkdtemp($0.baseAddress!) != nil }
            try Self.need(made, "exclusive temporary parent creation failed")
            rootPath = String(cString: template)
            let name = String(rootPath.dropFirst("/private/tmp/".count))
            try Self.need(name.hasPrefix("mrk-normal-project-") && !name.contains("/"), "unexpected temporary parent name")
            if profile == .projectFields {
                let refusedPath = rootPath + "/" + Self.androidRefusedDirectory
                try Self.need(refusedPath.split(separator: "/").count == 128 && refusedPath.utf8.count == 305,
                              "actual Android source refusal path census differs")
            }
            let root = try adoptDirectory(openat(temporary.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                parent: temporary.fd, name: name)
            directories[""] = root
            try Self.need(root.facts.uid == getuid() && root.facts.gid == getgid() && root.facts.mode & 0o7777 == 0o700,
                "temporary parent policy refused")
            for path in Self.ancestors(Set(originals.keys)) where !path.isEmpty {
                let (parent, name) = Self.parts(path), original = directories[parent]!
                try Self.need(mkdirat(original.fd, name, 0o700) == 0, "exclusive directory creation failed")
                let directory = try adoptDirectory(openat(original.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                    parent: original.fd, name: name)
                directories[path] = directory
                try Self.need(directory.facts.mode & 0o7777 == 0o700 && directory.facts.uid == getuid()
                    && directory.facts.gid == getgid(), "fixture directory policy refused")
            }
            for path in originals.keys.sorted() {
                let bytes = originals[path]!, (parent, name) = Self.parts(path), original = directories[parent]!
                let mode: mode_t = projectData && path.hasPrefix("sources/") ? 0o644 : 0o600
                let fd = openat(original.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
                try Self.need(fd >= 0, "exclusive file creation failed")
                do {
                    // Only this just-created fixture leaf is configured, never a
                    // selected user asset, host directory or existing source.
                    try Self.need(fchmod(fd, mode) == 0, "new fixture leaf mode failed")
                    try bytes.withUnsafeBytes { storage in
                        var offset = 0
                        while offset < storage.count {
                            let count = Darwin.write(fd, storage.baseAddress!.advanced(by: offset), storage.count - offset)
                            try Self.need(count > 0, "new fixture write failed"); offset += count
                        }
                    }
                } catch {
                    if Darwin.close(fd) != 0 { closeErrors.append("created-leaf-close") }
                    throw error
                }
                if Darwin.close(fd) != 0 { closeErrors.append("created-leaf-close") }
                let saved = try read(path)
                try Self.need(saved.bytes == bytes && saved.facts.mode & 0o7777 == mode, "new fixture readback failed")
                current[path] = saved
            }
            try checkRoster()
            if profile == .projectFields {
                try Self.need(current.count == 22 && directories.count == 143 && anchors.count == 3
                    && descriptors.count == 146, "created Android source fixture census differs")
            }
            if profile == .workflowRefusal {
                try Self.need(current.count == 15 && directories.count == 10 && anchors.count == 3
                    && descriptors.count == 13, "created managed workflow fixture census differs")
            }
            print("MRK_NORMAL_PROJECT_FIXTURE=retained-for-disposable-job-retirement;path=\(rootPath);bytes=\(current.values.reduce(0) { $0 + $1.bytes.count })")
        }
        // Read-only admission BEFORE app launch. This does not adopt an existing
        // store, create a substitute app-data location, or inspect a Keychain.
        func admitDefaultVault() throws {
            try Self.need(applicationSupport == nil && applicationDirectory == nil && vaultDirectory == nil,
                          "default-store admission repeated")
            var parent = try adoptDirectory(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: nil, name: "/")
            anchors.append(parent)
            for name in ["Users", "runner", "Library", "Application Support"] {
                parent = try adoptDirectory(openat(parent.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                                            parent: parent.fd, name: name)
                anchors.append(parent)
                try Self.need((parent.facts.uid == 0 || parent.facts.uid == getuid()) && parent.facts.mode & 0o022 == 0,
                              "default-store ancestor policy refused")
            }
            applicationSupport = parent
            try assertDefaultVaultAbsent()
        }
        func assertDefaultVaultAbsent() throws {
            guard let support = applicationSupport else { throw Refusal.condition("fixture: default-store admission absent") }
            try checkDirectory(support)
            var info = stat()
            let result = fstatat(support.fd, Self.applicationName, &info, AT_SYMLINK_NOFOLLOW)
            let error = errno
            try Self.need(result == -1 && error == ENOENT, "existing default app-data is not task-owned")
            // A bounded namespace observation supplements the exact NoFollow
            // lookup. It never reads or changes unrelated sibling contents.
            try Self.need(try children(support).allSatisfy { $0.precomposedStringWithCanonicalMapping.lowercased() != Self.applicationName },
                          "default app-data namespace collision")
        }
        private func privateStoreDirectory(_ parent: Directory, name: String) throws -> Directory {
            try checkDirectory(parent)
            let directory = try adoptDirectory(openat(parent.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                                               parent: parent.fd, name: name)
            try Self.need(directory.facts.uid == getuid() && directory.facts.gid == getgid()
                && directory.facts.mode & 0o7777 == 0o700 && directory.facts.flags == 0
                && directory.facts.device == parent.facts.device, "new default-store directory policy refused")
            return directory
        }
        private func storeSnapshot() throws -> [String: File] {
            guard let support = applicationSupport else { throw Refusal.condition("fixture: default-store admission absent") }
            try checkDirectory(support)
            if applicationDirectory == nil { applicationDirectory = try privateStoreDirectory(support, name: Self.applicationName) }
            guard let app = applicationDirectory else { throw Refusal.condition("fixture: default app-data missing") }
            try Self.need(try children(app) == ["credential-vault-v1"], "unexpected default app-data output")
            if vaultDirectory == nil { vaultDirectory = try privateStoreDirectory(app, name: "credential-vault-v1") }
            guard let vault = vaultDirectory else { throw Refusal.condition("fixture: default vault missing") }
            let names = try children(vault)
            let controls = Set(Self.storeControls.keys)
            let records = names.subtracting(controls)
            try Self.need(names.isSuperset(of: controls) && records.count <= 2 && records.allSatisfy { name in
                let suffix = name.dropFirst("record-".count)
                return name.hasPrefix("record-") && suffix.utf8.count == 32
                    && suffix.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
            }, "unexpected default-store roster or mutation debris")
            let canaries = ["private-envelope-only-canary", "MRK-inert-password-v1", "MRK-inert-password-v2",
                            "Synthetic distribution input", "Synthetic distribution replacement", "Synthetic profile input"]
            var result: [String: File] = [:]
            var identities: Set<String> = []
            var total = 0
            for name in names.sorted() {
                let file = try readLeaf(vault, name: name, privateOnly: true)
                try Self.need(identities.insert("\(file.facts.device):\(file.facts.inode)").inserted,
                              "default-store leaves alias one original")
                if let length = Self.storeControls[name] { try Self.need(file.bytes.count == length, "default-store control length") }
                else { try Self.need(file.bytes.count >= 248, "default-store record framing length") }
                total += file.bytes.count
                try Self.need(total <= 64 * 1024 && canaries.allSatisfy { file.bytes.range(of: Data($0.utf8)) == nil },
                              "default-store byte bound or synthetic plaintext canary")
                result[name] = file
            }
            try Self.need(try children(vault) == names, "default-store roster changed during readback")
            try checkDirectory(app); try checkDirectory(support)
            return result
        }
        func acceptStore(_ change: StoreChange) throws {
            let observed = try storeSnapshot()
            let controls = Set(Self.storeControls.keys)
            let before = Set(storeCurrent.keys), after = Set(observed.keys)
            var changed: Set<String> = []
            switch change {
            case .initialize:
                try Self.need(storeCurrent.isEmpty && after == controls && p12Record == nil && profileRecord == nil,
                              "default-store initialization stage")
            case .saveP12:
                let added = after.subtracting(before)
                try Self.need(before == controls && p12Record == nil && added.count == 1 && after.isSuperset(of: before),
                              "default-store P12 save stage")
                p12Record = added.first
            case .saveProfile:
                let added = after.subtracting(before)
                try Self.need(p12Record != nil && profileRecord == nil && before.count == 4
                    && added.count == 1 && after.isSuperset(of: before), "default-store profile save stage")
                profileRecord = added.first
            case .replaceP12:
                guard let name = p12Record, let old = storeCurrent[name], let new = observed[name] else {
                    throw Refusal.condition("fixture: replacement original missing")
                }
                try Self.need(!replacedP12 && profileRecord != nil && before.count == 5 && after == before
                    && new.facts.inode != old.facts.inode && new.bytes != old.bytes, "default-store replacement stage")
                changed.insert(name); replacedP12 = true
            case .deleteProfile:
                guard let name = profileRecord else { throw Refusal.condition("fixture: removal original missing") }
                try Self.need(replacedP12 && !deletedProfile && before.count == 5 && after == before.subtracting([name]),
                              "default-store removal stage")
                changed.insert(name); deletedProfile = true
            }
            for (name, old) in storeCurrent where !changed.contains(name) {
                guard let current = observed[name] else { throw Refusal.condition("fixture: unrelated store original disappeared") }
                try Self.need(current.facts == old.facts && current.bytes == old.bytes, "unrelated store original changed")
            }
            storeCurrent = observed
            try assertUnchanged()
        }
        func assertStoreUnchanged() throws {
            try Self.need(!storeCurrent.isEmpty, "default-store baseline absent")
            let current = try storeSnapshot()
            try Self.need(Set(current.keys) == Set(storeCurrent.keys), "default-store roster changed")
            for (name, before) in storeCurrent {
                guard let after = current[name] else { throw Refusal.condition("fixture: default-store original disappeared") }
                try Self.need(before.facts == after.facts && before.bytes == after.bytes, "default-store original changed")
            }
            try assertUnchanged()
        }
        func text(_ path: String, stage: String? = nil) throws -> String {
            let bytes = stage.flatMap { changes[$0]?[path] } ?? originals[path]
            guard let bytes, let text = String(data: bytes, encoding: .utf8) else {
                throw Refusal.condition("fixture: expected fixed UTF-8 DATA missing")
            }
            return text
        }
        func digest(_ path: String) throws -> String {
            guard let bytes = originals[path] else { throw Refusal.condition("fixture: fixed image DATA missing") }
            return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        }
        func assertUnchanged() throws {
            for path in current.keys.sorted() {
                let old = current[path]!, observed = try read(path)
                try Self.need(old.bytes == observed.bytes && old.facts == observed.facts, "unexpected file change: " + path)
            }
            try checkRoster()
        }
        func accept(_ stage: String) throws {
            guard let update = changes[stage], !acceptedStages.contains(stage) else {
                throw Refusal.condition("fixture: unknown or repeated stage")
            }
            let expectedPaths = Set(current.keys).union(update.keys)
            for path in Self.ancestors(expectedPaths) where directories[path] == nil {
                let (parent, name) = Self.parts(path), original = directories[parent]!
                try checkDirectory(original)
                let directory = try adoptDirectory(openat(original.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                    parent: original.fd, name: name)
                try Self.need(directory.facts.uid == getuid() && directory.facts.gid == getgid()
                    && directory.facts.mode & 0o7022 == 0, "new app directory policy refused")
                directories[path] = directory
            }
            var next: [String: File] = [:]
            for path in expectedPaths.sorted() {
                let observed = try read(path)
                if let bytes = update[path] {
                    try Self.need(observed.bytes == bytes, "exact expected bytes differ: " + path)
                    if let old = current[path] {
                        try Self.need(observed.facts.mode == old.facts.mode, "replacement changed original mode: " + path)
                    } else {
                        try Self.need([mode_t(0o600), mode_t(0o644)].contains(observed.facts.mode & 0o7777),
                            "unexpected new public-file mode")
                    }
                } else {
                    let old = current[path]!
                    try Self.need(old.bytes == observed.bytes && old.facts == observed.facts, "unrelated original changed: " + path)
                }
                next[path] = observed
            }
            try Self.need(next.values.reduce(0) { $0 + $1.bytes.count } <= 256 * 1024, "runtime fixture byte limit")
            current = next
            try checkRoster()
            acceptedStages.insert(stage)
        }
        func closeOriginals() throws {
            // Consume each original exactly once, including after partial setup.
            // Never retry close or search/reopen a replacement descriptor.
            while let fd = descriptors.popLast() {
                if Darwin.close(fd) != 0 { closeErrors.append("directory-close") }
            }
            directories.removeAll(); anchors.removeAll()
            applicationSupport = nil; applicationDirectory = nil; vaultDirectory = nil
            try Self.need(closeErrors.isEmpty, "original close errors: " + closeErrors.joined(separator: ","))
        }
    }


    @MainActor private var ownedFixture: LocalFixture?
    @MainActor private var journeyDeadline: TimeInterval?
    @MainActor private var journeyStage = "not-started"

    // Fixed terminal headings from the shipped controllers, not arbitrary text
    // scanning. A terminal refusal wakes the same bounded wait immediately.
    private static let configurationFailures = [
        "Native status did not match the reviewed contract", "Native window authority changed",
        "Native cleanup needs attention", "Native confirmation is unavailable",
        "Changes committed; completion is unverified", "Native save outcome or cleanup is unverified",
        "Changes committed; the save did not finish normally", "Not saved; originals restored by this operation",
        "Save session ended; draft retained", "Review these configuration issues", "The draft could not be validated"
    ]
    private static let workflowFailures = [
        "Native workflow status violated its contract", "Native workflow confirmation is unavailable",
        "Native document authority changed", "Native cleanup needs attention",
        "Workflow changes committed; completion unverified", "Workflow outcome or cleanup is unverified",
        "Workflows committed; recovery attention required", "Workflow transaction needs recovery attention",
        "Workflows committed; installation did not finish normally", "Not installed; original transaction changes rolled back",
        "Local workflow bundle refused", "Workflow review ended; configuration draft kept",
        "Setup preview unavailable", "Draft needs correction"
    ]
    private static let textFailures = [
        "Text status could not be verified", "Text written; completion not confirmed", "Text save or cleanup is unconfirmed",
        "Text written; recovery needs attention", "Text recovery needs attention", "Text written; completion needs attention",
        "This save’s changes were undone", "Text review ended; draft kept", "Text could not be loaded; earlier draft kept",
        "Text validation was not accepted", "Text corrections required"
    ]
    private static let versionFailures = [
        "Original version operation settled — no success assumed", "Original version outcome or cleanup is unverified",
        "Original ownership is unverified. A later observer or missing reply cannot authorize another save."
    ]
    private static let imageFailures = [
        "Original image operation is unverified", "Image copy or cleanup is unconfirmed", "Image recovery needs attention",
        "Images written; completion needs attention", "Original image review ended", "Original image selection refused",
        "Image operation status needs attention"
    ]
    private static let privateInputFailures = [
        "The session action was not confirmed", "Private input is unavailable in this build",
        "Encrypted storage is unavailable:", "unknown", "late-known"
    ]
    @MainActor private func remaining(_ requested: TimeInterval) throws -> TimeInterval {
        guard let clock = caseClock, let deadline = journeyDeadline else {
            throw Refusal.condition("original case deadline missing in " + journeyStage)
        }
        try checkOriginalOwners()
        return try clock.remaining(requested, before: deadline)
    }
    @MainActor private func stage(_ name: String, _ body: () throws -> Void) throws {
        journeyStage = name
        _ = try remaining(300)
        print("MRK_NORMAL_PROJECT_STAGE=\(name);result=started")
        do { try body() }
        catch {
            print("MRK_NORMAL_PROJECT_STAGE=\(name);result=failed;laterStages=not-run")
            throw error
        }
        print("MRK_NORMAL_PROJECT_STAGE=\(name);result=passed")
    }
    @MainActor private func named(_ root: XCUIElement, _ label: String) -> XCUIElementQuery {
        root.descendants(matching: .any).matching(identifier: label)
    }
    @MainActor private func controls(_ root: XCUIElement, _ types: [XCUIElement.ElementType],
                                    label: String, prefix: Bool = false) -> XCUIElementQuery {
        let predicate = NSPredicate(format: "elementType IN %@ AND label " + (prefix ? "BEGINSWITH %@" : "== %@"),
                                    types.map { NSNumber(value: $0.rawValue) }, label)
        return root.descendants(matching: .any).matching(predicate)
    }
    @MainActor private func diagnostic(_ root: XCUIElement) {
        // No debugDescription/tree dump, unknown labels, screen contents or
        // screenshots are published. Counts remain small scalar diagnostics.
        print("MRK_NORMAL_PROJECT_QUERY=stage:\(journeyStage);buttons:\(min(root.buttons.count, 256));textFields:\(min(root.textFields.count, 256));comboBoxes:\(min(root.comboBoxes.count, 256));sheets:\(min(root.sheets.count, 16))")
    }
    @MainActor private func waitElement(_ query: XCUIElementQuery, in root: XCUIElement,
                                       enabled: Bool = false, timeout: TimeInterval = 5,
                                       failures: [String] = []) throws -> XCUIElement {
        let first = query.element(boundBy: 0)
        let failed = root.staticTexts.matching(NSPredicate(format: "label IN %@", failures))
        let targets: NSDictionary = ["ready": first, "failed": failed.element(boundBy: 0)]
        let ready = "ready.exists == true" + (enabled ? " AND ready.enabled == true" : "")
        let predicate = NSPredicate(format: "(" + ready + ") OR failed.exists == true")
        let expected = XCTNSPredicateExpectation(predicate: predicate, object: targets)
        let result = XCTWaiter.wait(for: [expected], timeout: try remaining(timeout))
        if failed.count > 0 {
            diagnostic(root)
            throw Refusal.condition("terminal UI refusal in " + journeyStage)
        }
        if result != .completed || query.count != 1 {
            diagnostic(root)
            throw Refusal.condition("missing or ambiguous expected control in " + journeyStage)
        }
        try require(first.exists && (!enabled || first.isEnabled), "expected UI condition disappeared")
        return first
    }
    @MainActor private func waitGone(_ element: XCUIElement, timeout: TimeInterval = 5) throws {
        let wait = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: element)
        try require(XCTWaiter.wait(for: [wait], timeout: try remaining(timeout)) == .completed,
                    "owned UI did not dismiss in " + journeyStage)
    }
    @MainActor private func reveal(_ element: XCUIElement, in renderer: XCUIElement) throws {
        // Scroll only the original renderer; never an arbitrary screen position,
        // another application or a filesystem/default-location setter.
        for direction in [-1.0, 1.0] {
            for _ in 0..<8 {
                if element.isHittable { return }
                _ = try remaining(5)
                renderer.scroll(byDeltaX: 0, deltaY: CGFloat(direction * 550))
            }
        }
        try require(element.isHittable, "expected renderer control could not be revealed in " + journeyStage)
    }
    @MainActor private func press(_ root: XCUIElement, _ label: String, renderer: XCUIElement,
                                 failures: [String] = [], timeout: TimeInterval = 5) throws {
        let item = try waitElement(root.buttons.matching(identifier: label), in: root, enabled: true,
                                   timeout: timeout, failures: failures)
        try reveal(item, in: renderer)
        item.click()
    }
    @MainActor private func field(_ root: XCUIElement, _ label: String, multiline: Bool = false) throws -> XCUIElement {
        try waitElement(controls(root, [multiline ? .textView : .textField], label: label, prefix: true), in: root)
    }
    @MainActor private func replace(_ input: XCUIElement, with text: String, renderer: XCUIElement) throws {
        try require(input.isEnabled, "selected synthetic field is disabled")
        try reveal(input, in: renderer)
        input.click()
        input.typeKey("a", modifierFlags: .command)
        input.typeText(text)
        try require(input.value as? String == text, "typed synthetic field did not retain its exact value")
    }
    @MainActor private func select(_ root: XCUIElement, label: String, value: String,
                                  renderer: XCUIElement) throws {
        let control = try waitElement(controls(root, [.popUpButton, .comboBox], label: label, prefix: true),
                                     in: root, enabled: true)
        try reveal(control, in: renderer)
        control.click()
        // Native/web popup's own menu only, never the app's unrelated menus.
        let item = try waitElement(control.menuItems.matching(identifier: value), in: control, enabled: true)
        try require(item.isHittable, "owned selection menu item is not actionable")
        item.click()
        try require(control.value as? String == value, "selected value was not observed")
    }
    @MainActor private func expand(_ root: XCUIElement, prefix: String, renderer: XCUIElement) throws {
        let item = try waitElement(controls(root, [.disclosureTriangle, .button], label: prefix, prefix: true), in: root, enabled: true)
        try reveal(item, in: renderer)
        item.click() // Each fixed details element starts closed in this journey.
    }
    @MainActor private func displayed(_ root: XCUIElement, label: String, equals expected: String) throws {
        let item = try waitElement(named(root, label), in: root)
        // One complete bounded accessible text value, never a concatenation of
        // guessed/truncated snapshots. CR/LF byte proof comes from file readback.
        let value: String?
        if let direct = item.value as? String, !direct.isEmpty { value = direct }
        else if item.staticTexts.count == 1 { value = item.staticTexts.element(boundBy: 0).label }
        else { value = nil }
        let normalized = expected.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
        try require(value == normalized, "complete reviewed public text unavailable or different: " + label)
    }
    @MainActor private func inventory(_ root: XCUIElement, caption: String, paths: [String]) throws {
        let table = try waitElement(root.tables.matching(identifier: caption), in: root)
        try require(table.descendants(matching: .tableRow).count == paths.count + 1, "review inventory row count differs")
        for path in paths {
            _ = try unique(table.staticTexts.matching(identifier: path), "fixed review path is missing or repeated")
        }
    }
    @MainActor private func confirmedDialog(_ renderer: XCUIElement, title: String,
                                           action: String, checkbox: String, typedLabel: String? = nil) throws {
        let dialog = try waitElement(renderer.dialogs.matching(identifier: title), in: renderer)
        let apply = try unique(dialog.buttons.matching(identifier: action), "local affirmative action is ambiguous")
        try require(!apply.isEnabled, "sensitive local action began enabled without fresh consent")
        let checked = try waitElement(dialog.checkBoxes.matching(NSPredicate(format: "label BEGINSWITH %@", checkbox)), in: dialog, enabled: true)
        try require((checked.value as? String) == "0" || (checked.value as? NSNumber)?.intValue == 0,
                    "local consent started checked")
        try reveal(checked, in: renderer); checked.click()
        if let typedLabel {
            try require(!apply.isEnabled, "typed confirmation was not required")
            try replace(field(dialog, typedLabel), with: "SAVE", renderer: renderer)
        }
        let ready = try waitElement(dialog.buttons.matching(identifier: action), in: dialog, enabled: true)
        try reveal(ready, in: renderer); ready.click() // Exactly one Apply.
        try waitGone(dialog)
    }
    @MainActor private func nativeSheet(_ window: XCUIElement, title: String) throws -> XCUIElement {
        let sheet = try waitElement(window.sheets, in: window)
        if sheet.label != title && sheet.staticTexts.matching(identifier: title).count != 1 {
            diagnostic(sheet)
            throw Refusal.condition("unexpected original native sheet title in " + journeyStage)
        }
        return sheet
    }
    @MainActor private func goToFolder(_ sheet: XCUIElement, path: String) throws {
        try require(sheet.isHittable && path.hasPrefix("/private/tmp/mrk-normal-project-"),
                    "native navigation is not the owned synthetic fixture")
        sheet.typeKey("g", modifierFlags: [.command, .shift])
        let fields = sheet.descendants(matching: .any).matching(NSPredicate(
            format: "elementType IN %@ AND label IN %@",
            [XCUIElement.ElementType.textField, .comboBox].map { NSNumber(value: $0.rawValue) },
            ["Go to the folder:", "Go to folder:", "Go to Folder", "Go to the folder"]))
        let pathField = try waitElement(fields, in: sheet, enabled: true)
        try require(pathField.isHittable, "standard Go to Folder field is not actionable")
        pathField.click()
        pathField.typeKey("a", modifierFlags: .command)
        pathField.typeText(path)
        try require(pathField.value as? String == path, "native Go to Folder did not retain the exact fixture path")
        pathField.typeKey("\r", modifierFlags: [])
        try waitGone(pathField)
    }
    @MainActor private func nativeOpen(_ sheet: XCUIElement) throws {
        let open = try waitElement(sheet.buttons.matching(identifier: "Open"), in: sheet, enabled: true)
        try require(open.isHittable, "native Open is not actionable")
        open.click() // Browsing/typing alone was never selection.
        try waitGone(sheet)
    }
    @MainActor private func workflowDiff(_ text: String, path: String) -> String {
        // Independent presentation expectation over fixed DATA, not a call to
        // the production generator/writer or a hash returned by the application.
        let lines = text.hasSuffix("\n") ? String(text.dropLast()).components(separatedBy: "\n") : text.components(separatedBy: "\n")
        return "--- /dev/null\n+++ \(path)\n@@ -0,0 +1,\(lines.count) @@\n"
            + lines.map { "+" + $0 }.joined(separator: "\n") + "\n"
            + (text.hasSuffix("\n") ? "" : "\\ No newline at end of file\n")
    }

    @MainActor private func admittedJourneyApplication(profile: SourceProfile = .sameBuild) throws -> (URL, HostedAccount) {
        let account = try admitHostedAccount(profile)

        let url = URL(fileURLWithPath: "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app",
                      isDirectory: true)
        try require(Bundle(url: url)?.bundleIdentifier == "dev.mobile-release-kit.desktop.entry"
                    && (Bundle(url: url)?.object(forInfoDictionaryKey: "CFBundleExecutable") as? String) == "mrk-macos-entry"
                    && Bundle(url: url.appendingPathComponent("Contents/Helpers/MobileReleaseKitPayload.app"))?.bundleIdentifier == "dev.mobile-release-kit.desktop"
                    && (Bundle(url: url.appendingPathComponent("Contents/Helpers/MobileReleaseKitPayload.app"))?.object(forInfoDictionaryKey: "CFBundleExecutable") as? String) == "mobile-release-kit-desktop",
                    "the exact ordinary entry/payload installation is missing")
        return (url, account)
    }

    @MainActor private func launchForJourney() throws -> (XCUIApplication, XCUIElement, XCUIElement) {
        _ = try admittedJourneyApplication() // Every extended journey stays same-build.
        let app = try launchOrdinaryApplication()
        try require(app.wait(for: .runningForeground, timeout: try remaining(5)), "ordinary app did not enter the foreground")
        try require(app.windows.element(boundBy: 0).waitForExistence(timeout: try remaining(5)), "ordinary app has no visible main window")
        let window = try unique(app.windows, "ordinary main window is ambiguous")
        try require(window.isHittable, "ordinary main window is not usable")
        // Fixed renderer singleton diagnostic; no additional query or wait.
        let rendererQuery = window.webViews
        let rendererCount = rendererQuery.count
        if rendererCount != 1 {
            print("MRK_MACOS_NORMAL_RENDERER_QUERY=observation=initial;matches=\(min(rendererCount, 5));exceedsFour=\(rendererCount > 4 ? 1 : 0);nonAtomic=1")
        }
        try require(rendererCount == 1, "ordinary first-party renderer is missing or ambiguous")
        let renderer = rendererQuery.element(boundBy: 0)
        // End fixed renderer singleton diagnostic.
        try dashboard(renderer)
        return (app, window, renderer)
    }

    private enum PrivateInput: String {
        case p12 = "Apple Distribution identity", profile = "Apple provisioning profile"
        var file: String { self == .p12 ? "synthetic.p12" : "synthetic.mobileprovision" }
        var initialLabel: String { self == .p12 ? "Synthetic distribution input" : "Synthetic profile input" }
        var envelopeHelp: String { self == .p12
            ? "P12 envelope only: the password has not been tested, and no certificate, private key, expiry or signing identity has been verified."
            : "CMS envelope only: this does not establish an Apple issuer, profile validity, team, bundle ID or signing permission." }
    }
    @MainActor private func privateValue(_ storage: XCUIElement, _ root: XCUIElement,
                                        label: String, value: String, timeout: TimeInterval = 5) throws {
        let group = try waitElement(named(root, label), in: storage, timeout: timeout, failures: Self.privateInputFailures)
        _ = try waitElement(group.staticTexts.matching(identifier: value), in: storage,
                            timeout: timeout, failures: Self.privateInputFailures)
    }
    @MainActor private func privateStatus(_ storage: XCUIElement, action: String,
                                         phase: String = "idle", mutation: Bool = false) throws {
        let original = try waitElement(named(storage, "Original private-input operation"), in: storage,
                                       timeout: 48, failures: Self.privateInputFailures)
        try privateValue(storage, original, label: "Private-input operation action", value: action, timeout: 48)
        try privateValue(storage, original, label: "Private-input operation phase", value: phase, timeout: 48)
        try privateValue(storage, original, label: "Private-input operation settlement", value: "known", timeout: 48)
        if mutation {
            try privateValue(storage, original, label: "Private-input storage effect", value: "known-applied")
            try privateValue(storage, original, label: "Private-input storage durability", value: "confirmed")
            try privateValue(storage, original, label: "Private-input storage cleanup", value: "known")
        }
    }
    @MainActor private func privateContext(_ storage: XCUIElement, renderer: XCUIElement,
                                          explicitlySubmit: Bool = false) throws {
        if explicitlySubmit {
            try press(storage, "Submit current context", renderer: renderer, failures: Self.privateInputFailures)
        }
        _ = try waitElement(storage.staticTexts.matching(identifier: "Context submitted · not yet policy-validated"),
                            in: storage, timeout: 48, failures: Self.privateInputFailures)
    }
    @MainActor private func privateRecord(_ storage: XCUIElement, input: PrivateInput, label: String,
                                         revision: Int, assigned: Bool, notChecked: Bool = false) throws -> XCUIElement {
        let query = storage.descendants(matching: .any).matching(NSPredicate(
            format: "label BEGINSWITH %@ AND label ENDSWITH %@",
            "Private input · " + input.rawValue + " · item ", " · " + label))
        let row = try waitElement(query, in: storage, failures: Self.privateInputFailures)
        try privateValue(storage, row, label: "Private-input record revision", value: String(revision))
        _ = try waitElement(row.staticTexts.matching(identifier: assigned
            ? "Assigned to current submitted context" : "Not assigned to the current draft"), in: storage,
            failures: Self.privateInputFailures)
        if notChecked {
            _ = try waitElement(row.staticTexts.matching(identifier:
                "Payload not checked for the current session and draft. Assess this exact revision before assigning."),
                in: storage, failures: Self.privateInputFailures)
        }
        return row
    }
    @MainActor private func privateRecordIndex(_ row: XCUIElement, input: PrivateInput, label: String) throws -> Int {
        for index in 1...2 where row.label == "Private input · \(input.rawValue) · item \(index) · \(label)" { return index }
        throw Refusal.condition("fixed stored record has an unexpected accessible identity")
    }
    @MainActor private func privateRecordCount(_ storage: XCUIElement, count: Int, assigned: Int) throws {
        try require(storage.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", "Private input · ")).count == count,
                    "stored record count differs")
        try require(storage.staticTexts.matching(identifier: "Assigned to current submitted context").count == assigned,
                    "stored assignments appeared without the required explicit Bind")
    }
    @MainActor private func privateReview(_ storage: XCUIElement, title: String, target: String) throws -> XCUIElement {
        let review = try waitElement(named(storage, "Explicit private-input review"), in: storage,
                                     timeout: 48, failures: Self.privateInputFailures)
        _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", title)), in: storage, failures: Self.privateInputFailures)
        try privateValue(storage, review, label: "Private-input review target", value: target)
        return review
    }
    @MainActor private func privateAssessment(_ storage: XCUIElement, input: PrivateInput) throws {
        _ = try waitElement(storage.staticTexts.matching(NSPredicate(format: "title == %@", "Supplied-input assessment")), in: storage,
                            failures: Self.privateInputFailures)
        try require(storage.staticTexts.matching(identifier: "Configured only").count >= 1,
                    "mechanical supplied-input assessment did not configure this input")
        for label in [input.envelopeHelp, "Native validation: not run", "Service validation: not run", "Release readiness: unknown"] {
            _ = try waitElement(storage.staticTexts.matching(identifier: label), in: storage, failures: Self.privateInputFailures)
        }
    }
    @MainActor private func choosePrivate(_ storage: XCUIElement, window: XCUIElement, renderer: XCUIElement,
                                         fixture: LocalFixture, input: PrivateInput, replacement: String? = nil,
                                         cancel: Bool = false) throws {
        try select(storage, label: "What would you like to provide?", value: input.rawValue, renderer: renderer)
        try select(storage, label: "New or replacement copy?", value: replacement ?? "Save a new encrypted record", renderer: renderer)
        try press(storage, "Select file…", renderer: renderer, failures: Self.privateInputFailures)
        let sheet = try nativeSheet(window, title: "Choose a signing or iOS build-input file")
        if cancel {
            try click(sheet.buttons.matching(identifier: "Cancel"), "owned signing-input Cancel unavailable")
            try waitGone(sheet)
        } else {
            try goToFolder(sheet, path: fixture.sourcesPath)
            let file = try waitElement(controls(sheet, [.cell, .outlineRow, .tableRow, .icon], label: input.file),
                                      in: sheet, enabled: true)
            try require(file.isHittable, "owned inert signing-input file is not actionable")
            file.click()
            try require(file.isSelected, "native inert-file selection was not observed")
            try nativeOpen(sheet)
            try privateStatus(storage, action: "choose-file", phase: "selected")
        }
        try fixture.assertUnchanged()
    }
    @MainActor private func savePrivate(_ storage: XCUIElement, renderer: XCUIElement, fixture: LocalFixture,
                                       input: PrivateInput, label: String, reviewTarget: String,
                                       replacement: Bool = false) throws {
        if input == .p12 {
            let password = try waitElement(controls(storage, [.secureTextField], label: "P12 export password", prefix: true),
                                           in: storage, enabled: true, failures: Self.privateInputFailures)
            try reveal(password, in: renderer); password.click()
            // Fictional DATA typed into the ordinary write-only field. Do not
            // inspect its masked value, use the clipboard or change app state.
            password.typeText(replacement ? "MRK-inert-password-v2" : "MRK-inert-password-v1")
        }
        try replace(field(storage, "Vault label (optional)"), with: label, renderer: renderer)
        try press(storage, "Prepare private review", renderer: renderer, failures: Self.privateInputFailures)
        try privateStatus(storage, action: "prepare", phase: "preview")
        try privateAssessment(storage, input: input)
        let review = try privateReview(storage, title: "Save this encrypted input?", target: reviewTarget)
        try fixture.assertUnchanged()
        try press(review, "Save encrypted copy", renderer: renderer, failures: Self.privateInputFailures)
        try privateStatus(storage, action: "commit", mutation: true)
        try require(named(storage, "Explicit private-input review").count == 0, "saving retained an assignment review")
    }
    @MainActor private func assignPrivate(_ storage: XCUIElement, renderer: XCUIElement, fixture: LocalFixture,
                                         input: PrivateInput, label: String, revision: Int) throws {
        let row = try privateRecord(storage, input: input, label: label, revision: revision, assigned: false)
        let index = try privateRecordIndex(row, input: input, label: label)
        try press(row, "Assess and assign…", renderer: renderer, failures: Self.privateInputFailures)
        try privateStatus(storage, action: "prepare", phase: "preview")
        try privateAssessment(storage, input: input)
        let review = try privateReview(storage, title: "Assign this record to the submitted context?",
            target: "\(input.rawValue) · \(label) · item \(index) · revision \(revision)")
        try fixture.assertStoreUnchanged()
        try press(review, "Assign to this context", renderer: renderer, failures: Self.privateInputFailures)
        try privateStatus(storage, action: "bind")
        _ = try privateRecord(storage, input: input, label: label, revision: revision, assigned: true)
        try fixture.assertStoreUnchanged()
    }
    @MainActor private func lockPrivateVault(_ storage: XCUIElement, renderer: XCUIElement,
                                            fixture: LocalFixture, preservedMutation: Bool = false) throws {
        try press(storage, "Lock vault…", renderer: renderer, failures: Self.privateInputFailures)
        let consent = try waitElement(named(storage, "Confirm private-input lock"), in: storage,
                                      failures: Self.privateInputFailures)
        try press(consent, "Lock vault", renderer: renderer, failures: Self.privateInputFailures)
        _ = try waitElement(storage.staticTexts.matching(identifier: "Storage closed"), in: storage,
                            timeout: 48, failures: Self.privateInputFailures)
        try privateStatus(storage, action: preservedMutation ? "commit" : "lock", mutation: preservedMutation)
        try privateRecordCount(storage, count: 0, assigned: 0)
        try fixture.assertStoreUnchanged()
    }
    @MainActor private func openAndUnlockPrivateVault(_ storage: XCUIElement, renderer: XCUIElement) throws {
        try press(storage, "Open encrypted vault", renderer: renderer, failures: Self.privateInputFailures)
        try privateStatus(storage, action: "open-vault")
        _ = try waitElement(storage.staticTexts.matching(identifier: "Encrypted vault · locked"), in: storage,
                            failures: Self.privateInputFailures)
        try privateRecordCount(storage, count: 0, assigned: 0)
        try press(storage, "Unlock vault", renderer: renderer, failures: Self.privateInputFailures)
        try privateStatus(storage, action: "unlock")
        _ = try waitElement(storage.staticTexts.matching(identifier: "Encrypted vault · unlocked"), in: storage,
                            failures: Self.privateInputFailures)
    }
    @MainActor private func reopenPrivateVault(_ storage: XCUIElement, renderer: XCUIElement,
                                              fixture: LocalFixture) throws {
        try openAndUnlockPrivateVault(storage, renderer: renderer)
        try privateContext(storage, renderer: renderer, explicitlySubmit: true)
        try privateRecordCount(storage, count: 2, assigned: 0)
        for input in [PrivateInput.p12, .profile] {
            _ = try privateRecord(storage, input: input, label: input.initialLabel, revision: 1, assigned: false, notChecked: true)
        }
        try fixture.assertStoreUnchanged()
    }

    @MainActor func testSyntheticPersistentCredentials() throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300)
        let fixture = LocalFixture()
        ownedFixture = fixture
        try stage("persistence-admission") {
            _ = try admittedJourneyApplication()
            try fixture.admitDefaultVault() // Before any application launch.
            try fixture.prepare(.persistentCredentials)
        }
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("persistence-launch") {
            try fixture.assertDefaultVaultAbsent()
            launched = try launchForJourney()
        }
        guard let (app, window, renderer) = launched else { throw Refusal.condition("ordinary launch returned no original") }
        var selectedStorage: XCUIElement?
        try stage("persistence-project-and-initialize") {
            try press(renderer, "Open project folder", renderer: renderer)
            let project = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(project, path: fixture.projectPath); try nativeOpen(project)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "selected persistence project differs")
            try press(renderer, "Credentials", renderer: renderer)
            let storage = try waitElement(named(renderer, "Private-input storage controls"), in: renderer)
            selectedStorage = storage
            try select(storage, label: "Platform", value: "iOS", renderer: renderer)
            try select(storage, label: "Release stage", value: "Candidate / internal testing", renderer: renderer)
            try select(storage, label: "Input purpose", value: "Build / signing only", renderer: renderer)
            try press(storage, "Open encrypted vault", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "open-vault")
            _ = try waitElement(storage.staticTexts.matching(identifier: "Encrypted vault · uninitialized"), in: storage,
                                failures: Self.privateInputFailures)
            try fixture.assertDefaultVaultAbsent()
            try privateRecordCount(storage, count: 0, assigned: 0)
            try press(storage, "Review vault initialization…", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "prepare-initialize", phase: "preview")
            let review = try privateReview(storage, title: "Create a new encrypted vault?", target: "New encrypted private-input vault")
            try privateRecordCount(storage, count: 0, assigned: 0)
            try fixture.assertUnchanged()
            try press(review, "Create encrypted vault", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "initialize", mutation: true)
            _ = try waitElement(storage.staticTexts.matching(identifier: "Encrypted vault · unlocked"), in: storage,
                                failures: Self.privateInputFailures)
            try fixture.acceptStore(.initialize)
            try privateContext(storage, renderer: renderer, explicitlySubmit: true)
            try privateRecordCount(storage, count: 0, assigned: 0)
        }
        guard let storage = selectedStorage else { throw Refusal.condition("ordinary private-input controls missing") }
        for input in [PrivateInput.p12, .profile] {
            try stage(input == .p12 ? "persistence-save-and-bind-p12" : "persistence-save-and-bind-profile") {
                try choosePrivate(storage, window: window, renderer: renderer, fixture: fixture, input: input)
                try savePrivate(storage, renderer: renderer, fixture: fixture, input: input, label: input.initialLabel,
                                reviewTarget: "New \(input.rawValue.lowercased()) encrypted record")
                try fixture.acceptStore(input == .p12 ? .saveP12 : .saveProfile)
                _ = try privateRecord(storage, input: input, label: input.initialLabel, revision: 1, assigned: false, notChecked: true)
                try privateRecordCount(storage, count: input == .p12 ? 1 : 2, assigned: input == .p12 ? 0 : 1)
                try assignPrivate(storage, renderer: renderer, fixture: fixture, input: input, label: input.initialLabel, revision: 1)
            }
        }
        try stage("persistence-context-invalidation") {
            try privateRecordCount(storage, count: 2, assigned: 2)
            try select(storage, label: "Input purpose", value: "Store access only", renderer: renderer)
            try privateContext(storage, renderer: renderer)
            try privateRecordCount(storage, count: 2, assigned: 0)
            try select(storage, label: "Input purpose", value: "Build / signing only", renderer: renderer)
            try privateContext(storage, renderer: renderer)
            try privateRecordCount(storage, count: 2, assigned: 0)
            try fixture.assertStoreUnchanged()
            for input in [PrivateInput.p12, .profile] {
                try assignPrivate(storage, renderer: renderer, fixture: fixture, input: input, label: input.initialLabel, revision: 1)
            }
        }
        try stage("persistence-lock-reopen-rebind") {
            try lockPrivateVault(storage, renderer: renderer, fixture: fixture)
            try reopenPrivateVault(storage, renderer: renderer, fixture: fixture)
            for input in [PrivateInput.p12, .profile] {
                try assignPrivate(storage, renderer: renderer, fixture: fixture, input: input, label: input.initialLabel, revision: 1)
            }
        }
        try stage("persistence-replacement-cancel") {
            let row = try privateRecord(storage, input: .p12, label: PrivateInput.p12.initialLabel, revision: 1, assigned: true)
            let index = try privateRecordIndex(row, input: .p12, label: PrivateInput.p12.initialLabel)
            try choosePrivate(storage, window: window, renderer: renderer, fixture: fixture, input: .p12,
                replacement: "Replace item \(index) · \(PrivateInput.p12.initialLabel) · revision 1", cancel: true)
            // The cancelled original owns a vault lease. Its STOP deliberately
            // retires the entire session, not just the selected assignment.
            _ = try waitElement(storage.staticTexts.matching(identifier: "Storage closed"), in: storage,
                                timeout: 48, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "choose-file")
            try privateRecordCount(storage, count: 0, assigned: 0)
            try fixture.assertStoreUnchanged()
            try reopenPrivateVault(storage, renderer: renderer, fixture: fixture)
        }
        try stage("persistence-replace-current-record") {
            let row = try privateRecord(storage, input: .p12, label: PrivateInput.p12.initialLabel, revision: 1, assigned: false)
            let index = try privateRecordIndex(row, input: .p12, label: PrivateInput.p12.initialLabel)
            try choosePrivate(storage, window: window, renderer: renderer, fixture: fixture, input: .p12,
                replacement: "Replace item \(index) · \(PrivateInput.p12.initialLabel) · revision 1")
            try savePrivate(storage, renderer: renderer, fixture: fixture, input: .p12, label: "Synthetic distribution replacement",
                reviewTarget: "\(PrivateInput.p12.rawValue) · \(PrivateInput.p12.initialLabel) · item \(index) · revision 1", replacement: true)
            try fixture.acceptStore(.replaceP12)
            try privateRecordCount(storage, count: 2, assigned: 0)
            _ = try privateRecord(storage, input: .p12, label: "Synthetic distribution replacement", revision: 2, assigned: false, notChecked: true)
            try assignPrivate(storage, renderer: renderer, fixture: fixture, input: .p12, label: "Synthetic distribution replacement", revision: 2)
        }
        try stage("persistence-delete-and-quit") {
            // Cancel/reopen cleared both bindings. Reassess and bind this same
            // persisted profile so Delete must revoke a live assignment too.
            try assignPrivate(storage, renderer: renderer, fixture: fixture, input: .profile,
                              label: PrivateInput.profile.initialLabel, revision: 1)
            try privateRecordCount(storage, count: 2, assigned: 2)
            let row = try privateRecord(storage, input: .profile, label: PrivateInput.profile.initialLabel, revision: 1, assigned: true)
            let index = try privateRecordIndex(row, input: .profile, label: PrivateInput.profile.initialLabel)
            try press(row, "Review removal…", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "prepare-delete", phase: "preview")
            let review = try privateReview(storage, title: "Remove this encrypted copy?",
                target: "\(PrivateInput.profile.rawValue) · \(PrivateInput.profile.initialLabel) · item \(index) · revision 1")
            try fixture.assertStoreUnchanged()
            try press(review, "Remove encrypted copy", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "commit", mutation: true)
            try fixture.acceptStore(.deleteProfile)
            try privateRecordCount(storage, count: 1, assigned: 1)
            _ = try privateRecord(storage, input: .p12, label: "Synthetic distribution replacement", revision: 2, assigned: true)
            try lockPrivateVault(storage, renderer: renderer, fixture: fixture, preservedMutation: true)
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "normal affirmative Quit unavailable")
            try completeNormalQuit(app)
            try fixture.assertStoreUnchanged()
        }
        var restarted: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("persistence-restart-launch") {
            try retainPersistenceLifetimeForRestart(app, fixture: fixture)
            restarted = try launchForJourney()
        }
        guard let (restartedApp, restartedWindow, restartedRenderer) = restarted else {
            throw Refusal.condition("second ordinary launch returned no original")
        }
        var restartedStorage: XCUIElement?
        try stage("persistence-restart-unlock") {
            try fixture.assertStoreUnchanged()
            try press(restartedRenderer, "Open project folder", renderer: restartedRenderer)
            let project = try nativeSheet(restartedWindow, title: "Choose a mobile project folder")
            try goToFolder(project, path: fixture.projectPath); try nativeOpen(project)
            _ = try waitElement(restartedRenderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: restartedRenderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(restartedRenderer.staticTexts.matching(identifier: fixture.projectPath), "restarted persistence project differs")
            try press(restartedRenderer, "Credentials", renderer: restartedRenderer)
            let storage = try waitElement(named(restartedRenderer, "Private-input storage controls"), in: restartedRenderer)
            restartedStorage = storage
            _ = try waitElement(storage.staticTexts.matching(identifier: "Storage closed"), in: storage,
                                failures: Self.privateInputFailures)
            try privateRecordCount(storage, count: 0, assigned: 0)
            try select(storage, label: "Platform", value: "iOS", renderer: restartedRenderer)
            try select(storage, label: "Release stage", value: "Candidate / internal testing", renderer: restartedRenderer)
            try select(storage, label: "Input purpose", value: "Build / signing only", renderer: restartedRenderer)
            // Same default vault/provider/helper, never a second Initialize or
            // fixture admission. Opening must be locked with no exposed rows.
            try openAndUnlockPrivateVault(storage, renderer: restartedRenderer)
            // Unlock normally submits the already-requested context. Wait for
            // that acknowledgement; another Submit would clear stale state and
            // obscure whether ordinary UI automatically assessed or assigned it.
            try privateContext(storage, renderer: restartedRenderer)
            try privateRecordCount(storage, count: 1, assigned: 0)
            _ = try privateRecord(storage, input: .p12, label: "Synthetic distribution replacement", revision: 2,
                                  assigned: false, notChecked: true)
            try fixture.assertStoreUnchanged()
        }
        guard let storageAfterRestart = restartedStorage else { throw Refusal.condition("restarted private-input controls missing") }
        try stage("persistence-restart-rebind-and-quit") {
            try assignPrivate(storageAfterRestart, renderer: restartedRenderer, fixture: fixture, input: .p12,
                              label: "Synthetic distribution replacement", revision: 2)
            try privateRecordCount(storageAfterRestart, count: 1, assigned: 1)
            try lockPrivateVault(storageAfterRestart, renderer: restartedRenderer, fixture: fixture)
            let sheet = try quitSheet(restartedApp, restartedWindow)
            try click(sheet.buttons.matching(identifier: "Quit"), "second normal affirmative Quit unavailable")
            try completeNormalQuit(restartedApp)
            try fixture.assertStoreUnchanged()
            try fixture.closeOriginals(); ownedFixture = nil
        }
        // Original XCTest counts/exit and independent native-owner evidence are
        // still required. Same installed app restart only, not upgrade/signing.
        try acceptPersistenceRestart()
        print("MRK_MACOS_NORMAL_PERSISTENCE_UI=initialize-save-assess-bind-context-lock-reopen-rebind-replace-delete-restart-unlock-reassess-rebind;appRestart=passed;ordinaryLifetimes=2;cleanExitStatus=unavailable;allWorkerFinality=unavailable;fixtures=retained-for-disposable-job-retirement")
    }

    @MainActor func testSyntheticProjectPathFields() throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300)
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("launch") { launched = try launchForJourney() }
        guard let (app, window, renderer) = launched else { throw Refusal.condition("ordinary launch returned no original") }
        let fixture = LocalFixture()
        ownedFixture = fixture
        try stage("fixture") { try fixture.prepare(.projectFields) }
        try stage("project-open") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(sheet, path: fixture.projectPath)
            try nativeOpen(sheet)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "selected project path is not exact")
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)
            try fixture.assertUnchanged()
        }

        // Six ordinary native source actions precede every project draft edit.
        // Public named role groups, not duplicate-button ordinals or test hooks.
        let androidRoleLabels = ["jdk": "Java development kit (JDK)",
                                 "sdk": "Android SDK", "gradle": "Gradle distribution"]
        var androidSelections: [String: String] = [:]
        @MainActor func androidGroup(_ role: String) throws -> XCUIElement {
            guard let label = androidRoleLabels[role] else {
                throw Refusal.condition("fixed Android source role is unknown")
            }
            return try waitElement(controls(renderer, [.group], label: label + " source folder"), in: renderer)
        }
        @MainActor func androidRetained() throws {
            for role in ["jdk", "sdk", "gradle"] {
                let group = try androidGroup(role)
                let chosen = androidSelections[role]
                if let name = chosen {
                    // WebKit may expose the strong text separately or coalesce
                    // that one paragraph. Both comparisons name the exact leaf.
                    let selected = group.staticTexts.matching(NSPredicate(
                        format: "label == %@ OR label CONTAINS %@", name,
                        "Selected folder: " + name + " · folder selection only."))
                    _ = try waitElement(selected, in: group, timeout: 48)
                } else {
                    _ = try waitElement(group.staticTexts.matching(NSPredicate(
                        format: "label CONTAINS %@", "No folder selected for this project.")), in: group)
                }
                _ = try waitElement(group.buttons.matching(identifier: chosen == nil
                    ? "Browse for folder" : "Choose a different folder"), in: group, enabled: true, timeout: 48)
            }
        }
        @MainActor func androidStatus(_ phase: String, reason: String) throws {
            let failures = ["No new folder-selection outcome was confirmed",
                            "Original folder cleanup could not be confirmed."]
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", phase)),
                                in: renderer, timeout: 48, failures: failures)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", reason)),
                                in: renderer, timeout: 48, failures: failures)
        }
        @MainActor func androidBrowse(_ role: String, title: String, relative: String,
                                      cancel: Bool = false, refused: Bool = false) throws {
            try require(!(cancel && refused), "fixed Android source outcome is ambiguous")
            let group = try androidGroup(role)
            try press(group, androidSelections[role] == nil ? "Browse for folder" : "Choose a different folder",
                      renderer: renderer, timeout: 48)
            let sheet = try nativeSheet(window, title: title)
            if cancel {
                try click(sheet.buttons.matching(identifier: "Cancel"), "owned Android source Cancel unavailable")
                try waitGone(sheet)
                try androidStatus("Folder selection cancelled.",
                                  reason: "The native folder dialog was closed without selecting a folder.")
            } else {
                try goToFolder(sheet, path: fixture.rootPath + "/" + relative)
                try nativeOpen(sheet) // Genuine enabled Open, never file exclusion or Cancel.
                if refused {
                    // Mac source parts rejects the 128th normal component
                    // before SourceBook.begin. Other outcomes must fail.
                    try androidStatus("Folder selection could not be used.",
                        reason: "Choose a real, readable local folder, not an alias or archive. This check does not inspect the tools inside it.")
                } else {
                    try androidStatus("Original folder selection retained.",
                        reason: "Folder selection alone is not supplier inspection or a protected copy. Check the separate original registration Status.")
                    guard let name = relative.split(separator: "/").last else {
                        throw Refusal.condition("fixed Android source leaf is absent")
                    }
                    androidSelections[role] = String(name)
                }
            }
            // Cancel/refusal never replace the prior three role selections.
            // Enabled Browse also waits for the original Status gate to settle.
            try androidRetained()
            try fixture.assertUnchanged()
        }
        try stage("android-source-jdk") {
            try press(renderer, "Releases", renderer: renderer)
            try androidRetained()
            try androidBrowse("jdk", title: "Choose an installed Java 17 JDK folder", relative: "sources/tool-jdk.jdk")
        }
        try stage("android-source-sdk") {
            try androidBrowse("sdk", title: "Choose the Android SDK folder", relative: "sources/tool-sdk")
        }
        try stage("android-source-gradle") {
            try androidBrowse("gradle", title: "Choose an extracted Gradle distribution folder", relative: "sources/tool-gradle")
        }
        try stage("android-source-cancel") {
            try androidBrowse("jdk", title: "Choose an installed Java 17 JDK folder", relative: "sources/tool-jdk.jdk", cancel: true)
        }
        try stage("android-source-reselect") {
            try androidBrowse("jdk", title: "Choose an installed Java 17 JDK folder", relative: "sources/tool-jdk-replacement.jdk")
        }
        try stage("android-source-refused") {
            try androidBrowse("jdk", title: "Choose an installed Java 17 JDK folder",
                              relative: LocalFixture.androidRefusedDirectory, refused: true)
        }

        @MainActor func settings(_ tab: String) throws {
            try press(renderer, "Project settings", renderer: renderer)
            let tabs = try waitElement(named(renderer, "Settings section"), in: renderer)
            try press(tabs, tab, renderer: renderer)
        }
        @MainActor func selected(_ label: String, relative: String) throws {
            _ = try waitElement(controls(renderer, [.textField], label: label, prefix: true)
                .matching(NSPredicate(format: "value == %@", relative)), in: renderer, timeout: 48)
            _ = try waitElement(renderer.buttons.matching(identifier: "Browse existing " + label),
                                in: renderer, enabled: true, timeout: 48)
        }
        @MainActor func browse(_ label: String, title: String, relative: String, file: Bool = false, cancel: Bool = false) throws {
            try press(renderer, "Browse existing " + label, renderer: renderer)
            let sheet = try nativeSheet(window, title: title)
            if cancel {
                try click(sheet.buttons.matching(identifier: "Cancel"), "owned project-field Cancel unavailable")
                try waitGone(sheet)
            } else {
                let path = fixture.projectPath + "/" + relative
                if file {
                    guard let separator = path.lastIndex(of: "/") else {
                        throw Refusal.condition("fixed project-field path has no parent")
                    }
                    let parent = String(path[..<separator])
                    let name = String(path[path.index(after: separator)...])
                    try goToFolder(sheet, path: parent)
                    let item = try waitElement(controls(sheet, [.cell, .outlineRow, .tableRow, .icon], label: name),
                                              in: sheet, enabled: true)
                    try require(item.isHittable, "owned project-field file is not actionable")
                    item.click()
                    try require(item.isSelected, "native project-field file selection was not observed")
                } else {
                    try goToFolder(sheet, path: path)
                }
                try nativeOpen(sheet)
            }
            // Native sheet dismissal is not by itself the asynchronous draft result.
            try selected(label, relative: relative)
            if cancel {
                _ = try waitElement(renderer.staticTexts.matching(identifier: "Selection cancelled. No draft or baseline was changed."),
                                    in: renderer)
            }
            try fixture.assertUnchanged()
        }
        try stage("field-version") {
            try settings("General")
            try browse("Committed version file", title: "Choose an existing version source inside the project",
                       relative: "inputs/VERSION", file: true)
        }
        try stage("field-project") {
            try settings("iOS")
            try browse("Xcode project", title: "Choose an existing Xcode project directory",
                       relative: "ios/Example.xcodeproj")
        }
        try stage("field-workspace") {
            try browse("Xcode workspace", title: "Choose an existing Xcode workspace directory",
                       relative: "ios/Example.xcworkspace")
            try selected("Xcode project", relative: "ios/Example.xcodeproj")
        }
        try stage("field-metadata") {
            try press(renderer, "Metadata", renderer: renderer)
            try browse("Store metadata folder", title: "Choose an existing metadata directory inside the project",
                       relative: "metadata")
        }
        try stage("field-file-cancel") {
            try settings("General")
            try browse("Committed version file", title: "Choose an existing version source inside the project",
                       relative: "inputs/VERSION", file: true, cancel: true)
        }
        try stage("field-directory-cancel") {
            try press(renderer, "Metadata", renderer: renderer)
            try browse("Store metadata folder", title: "Choose an existing metadata directory inside the project",
                       relative: "metadata", cancel: true)
        }
        try stage("field-review") {
            try press(renderer, "Metadata", renderer: renderer)
            try selected("Store metadata folder", relative: "metadata")
            try settings("General")
            try selected("Committed version file", relative: "inputs/VERSION")
            try settings("iOS")
            try selected("Xcode project", relative: "ios/Example.xcodeproj")
            try selected("Xcode workspace", relative: "ios/Example.xcworkspace")
            try press(renderer, "Review draft changes", renderer: renderer)
            _ = try waitElement(renderer.staticTexts.matching(identifier: "Current draft · retained baseline"), in: renderer)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Format validation needs attention")),
                                in: renderer)
            _ = try waitElement(renderer.staticTexts.matching(identifier: "invalid"), in: renderer)
            try fixture.assertUnchanged()
        }
        try stage("quit") {
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "normal affirmative Quit unavailable")
            try completeNormalQuit(app)
            try fixture.assertUnchanged()
            try fixture.closeOriginals()
            ownedFixture = nil
        }
        // Draft-only selection is not Save, release readiness, or all-worker finality.
        try acceptFinalScenario()
        print("MRK_MACOS_NORMAL_PROJECT_FIELDS_UI=ordinary-four-field-browse-two-cancels-draft-only-invalid-pair-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
        print("MRK_MACOS_NORMAL_ANDROID_SOURCE_UI=ordinary-jdk-sdk-gradle-native-cancel-jdk-reselect-backend-source-refused-selection-only;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }

    @MainActor func testSyntheticProjectLocalEdits() throws {
        try syntheticProjectJourney(includeImages: false)
    }
    @MainActor func testSyntheticProjectLocalEditsAndImages() throws {
        try syntheticProjectJourney(includeImages: true)
    }
    @MainActor private func syntheticProjectJourney(includeImages: Bool) throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300)
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("launch") { launched = try launchForJourney() }
        guard let (app, window, renderer) = launched else { throw Refusal.condition("ordinary launch returned no original") }
        let fixture = LocalFixture()
        ownedFixture = fixture
        try stage("fixture") { try fixture.prepare() }

        try stage("project-cancel") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try click(sheet.buttons.matching(identifier: "Cancel"), "native folder Cancel unavailable")
            try waitGone(sheet)
            try dashboard(renderer)
            try fixture.assertUnchanged()
        }
        try stage("project-open") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(sheet, path: fixture.projectPath)
            try nativeOpen(sheet)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "selected project path is not exact")
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)
            try fixture.assertUnchanged()
        }
        try stage("config") {
            try press(renderer, "Project settings", renderer: renderer)
            let settings = try waitElement(named(renderer, "Settings section"), in: renderer)
            try press(settings, "General", renderer: renderer)
            let candidate = try field(renderer, "Candidate branch")
            try require(candidate.value as? String == "main", "saved candidate branch was not loaded")
            try replace(candidate, with: "qa-candidate", renderer: renderer)
            try press(renderer, "Metadata", renderer: renderer)
            let locales = try waitElement(named(renderer, "Android locales"), in: renderer)
            try press(locales, "Add entry", renderer: renderer)
            try replace(field(locales, "Android locales, entry 2"), with: "fr-FR", renderer: renderer)
            // The SAME unsaved configuration must survive page navigation.
            try press(renderer, "Project settings", renderer: renderer)
            try require(field(renderer, "Candidate branch").value as? String == "qa-candidate", "navigation lost the branch draft")
            try press(renderer, "Metadata", renderer: renderer)
            try require(field(renderer, "Android locales, entry 2").value as? String == "fr-FR", "navigation lost the locale draft")
            try press(renderer, "Validate only", renderer: renderer)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Format validation complete")), in: renderer,
                                failures: Self.configurationFailures)
            try press(renderer, "Prepare save review", renderer: renderer, failures: Self.configurationFailures)
            let review = try waitElement(named(renderer, "Native configuration save"), in: renderer)
            _ = try waitElement(review.buttons.matching(identifier: "Apply reviewed save"), in: review,
                                enabled: true, timeout: 48, failures: Self.configurationFailures)
            try inventory(review, caption: "Exact native destination inventory", paths: ["release/mobile-release.json", ".gitignore"])
            for rule in [".mobile-release/"] + LocalFixture.controls.map({ $0 + "/" }) {
                _ = try unique(review.staticTexts.matching(identifier: rule), "fixed ignore addition is missing or duplicated")
            }
            try expand(review, prefix: "Inspect safe field-path changes; raw values are omitted", renderer: renderer)
            for label in ["Candidate branch", "Android locales"] {
                _ = try waitElement(review.staticTexts.matching(identifier: label), in: review)
            }
            try fixture.assertUnchanged()
            try press(review, "Apply reviewed save", renderer: renderer)
            try confirmedDialog(renderer, title: "Apply this configuration save?", action: "Apply reviewed save",
                                checkbox: "I reviewed this exact inventory and understand that cancellation may be too late after Apply.")
            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Submitted configuration saved")), in: review,
                                timeout: 48, failures: Self.configurationFailures)
            try fixture.accept("config")
            try press(renderer, "Dashboard", renderer: renderer)
            let earlier = try waitElement(renderer.staticTexts.matching(identifier: "This static observation predates the last settled save check"), in: renderer)
            try press(renderer, "Refresh static view", renderer: renderer)
            try waitGone(earlier)
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)
            try fixture.assertUnchanged()
        }
        try stage("github") {
            try press(renderer, "GitHub", renderer: renderer)
            try replace(field(renderer, "Toolkit repository"), with: "Example/mobile-release-kit", renderer: renderer)
            try replace(field(renderer, "Full toolkit commit"), with: String(repeating: "a", count: 40), renderer: renderer)
            let comparison = try unique(renderer.checkBoxes.matching(identifier: "Use a caller-supplied summary — no files are read"),
                                        "optional comparison control is unavailable")
            try require((comparison.value as? String) == "0" || (comparison.value as? NSNumber)?.intValue == 0,
                        "passive supplied comparison unexpectedly enabled")
            try press(renderer, "Preview GitHub setup", renderer: renderer)
            let proposal = try waitElement(named(renderer, "Read-only GitHub setup proposal"), in: renderer,
                                          failures: Self.workflowFailures)
            _ = try waitElement(proposal.staticTexts.matching(NSPredicate(format: "title == %@", "Four read-only workflow previews")), in: proposal)
            for path in LocalFixture.callers {
                let shownPath = String(path.dropFirst("project/".count))
                try expand(proposal, prefix: shownPath, renderer: renderer)
                try displayed(proposal, label: "Read-only proposed content for " + shownPath,
                              equals: fixture.text(path, stage: "workflows"))
            }
            try fixture.assertUnchanged() // All four destinations are still absent.
            let review = try waitElement(named(renderer, "Local GitHub workflow files"), in: renderer)
            try press(review, "Review local workflow files", renderer: renderer, failures: Self.workflowFailures)
            _ = try waitElement(review.buttons.matching(identifier: "Confirm reviewed local files"), in: review,
                                enabled: true, timeout: 48, failures: Self.workflowFailures)
            let paths = LocalFixture.callers.map { String($0.dropFirst("project/".count)) }
            try inventory(review, caption: "Complete native workflow inventory — all four or refuse", paths: paths)
            for path in LocalFixture.callers {
                let shownPath = String(path.dropFirst("project/".count))
                try expand(review, prefix: shownPath, renderer: renderer)
                try displayed(review, label: "Complete added diff for " + shownPath,
                              equals: workflowDiff(fixture.text(path, stage: "workflows"), path: shownPath))
            }
            try fixture.assertUnchanged()
            try press(review, "Confirm reviewed local files", renderer: renderer)
            try confirmedDialog(renderer, title: "Apply this four-caller bundle?", action: "Apply reviewed local files",
                                checkbox: "I reviewed all four paths and complete before/after text.")
            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Reviewed local workflow bundle installed")), in: review,
                                timeout: 48, failures: Self.workflowFailures)
            try fixture.accept("workflows")
        }
        try stage("text") {
            try press(renderer, "Metadata", renderer: renderer)
            let editor = try waitElement(named(renderer, "Configured public locale text")
                .containing(.button, identifier: "Validate text"), in: renderer)
            try select(editor, label: "Saved platform / locale", value: "android / fr-FR", renderer: renderer)
            try press(editor, "Load public text", renderer: renderer, failures: Self.textFailures)
            for (label, file) in [("App title", "title.txt"), ("Short description", "short_description.txt"), ("Full description", "full_description.txt")] {
                try require(field(editor, label, multiline: true).value as? String
                    == fixture.text("project/release/store/android/fr-FR/" + file), "original locale text was not loaded")
            }
            try replace(field(editor, "App title", multiline: true), with: fixture.text(LocalFixture.title, stage: "text"), renderer: renderer)
            try press(editor, "Validate text", renderer: renderer)
            _ = try waitElement(editor.staticTexts.matching(identifier: "Format-valid selected text"), in: editor, failures: Self.textFailures)
            try press(editor, "Review changes", renderer: renderer, failures: Self.textFailures)
            let review = try waitElement(named(renderer, "Original metadata file-save operation"), in: renderer)
            _ = try waitElement(review.buttons.matching(identifier: "Save text…"), in: review,
                                enabled: true, timeout: 48, failures: Self.textFailures)
            let names = ["title.txt", "short_description.txt", "full_description.txt"]
            let paths = names.map { "release/store/android/fr-FR/" + $0 }
            try inventory(review, caption: "Files in this review", paths: paths)
            for path in paths {
                try expand(review, prefix: path, renderer: renderer)
                try displayed(review, label: "Complete original public text for " + path, equals: fixture.text("project/" + path))
                try displayed(review, label: "Complete reviewed public text for " + path,
                              equals: fixture.text("project/" + path, stage: path.hasSuffix("/title.txt") ? "text" : nil))
            }
            try fixture.assertUnchanged()
            try press(review, "Save text…", renderer: renderer)
            try confirmedDialog(renderer, title: "Save this reviewed locale bundle?", action: "Save text",
                                checkbox: "I reviewed all exact paths, full original/replacement text, digests and line-ending changes.",
                                typedLabel: "Type SAVE to confirm only this local text operation")
            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Text saved")), in: review, timeout: 48, failures: Self.textFailures)
            try fixture.accept("text")
            let older = try waitElement(editor.staticTexts.matching(identifier:
                "The passive observation predates the original settled save check. Saved facts come from that exact native plan, not a fabricated fresh file read."), in: editor)
            try press(editor, "Refresh text", renderer: renderer, failures: Self.textFailures)
            try waitGone(older)
            try require(field(editor, "App title", multiline: true).value as? String == fixture.text(LocalFixture.title, stage: "text"),
                        "fresh text observation did not preserve the saved value")
            try fixture.assertUnchanged()
        }
        try stage("version") {
            try press(renderer, "Dashboard", renderer: renderer)
            let editor = try waitElement(named(renderer, "Edit or create saved version values"), in: renderer)
            try press(editor, "Open saved version editor", renderer: renderer, failures: Self.versionFailures)
            let name = try field(editor, "Marketing version"), build = try field(editor, "Build number")
            try require(name.value as? String == "1.2.3" && build.value as? String == "7", "original version was not loaded")
            try replace(name, with: "2.3.4", renderer: renderer)
            try replace(build, with: "8", renderer: renderer)
            try press(editor, "Validate and review values", renderer: renderer, failures: Self.versionFailures)
            _ = try waitElement(editor.buttons.matching(identifier: "Save version values…"), in: editor,
                                enabled: true, timeout: 48, failures: Self.versionFailures)
            try displayed(editor, label: "Complete original version source", equals: fixture.text(LocalFixture.version))
            try displayed(editor, label: "Complete reviewed version source", equals: fixture.text(LocalFixture.version, stage: "version"))
            try fixture.assertUnchanged()
            try press(editor, "Save version values…", renderer: renderer)
            try confirmedDialog(renderer, title: "Save these reviewed version values?", action: "Save version values",
                                checkbox: "I reviewed the full original/after text, exact destination, byte comparisons, mode and directory/line-ending facts.",
                                typedLabel: "Type SAVE to confirm this local operation")
            _ = try waitElement(editor.staticTexts.matching(identifier: "Submitted version values saved"), in: editor,
                                timeout: 48, failures: Self.versionFailures)
            try fixture.accept("version")
            let saved = try waitElement(named(renderer, "Saved version and build"), in: renderer)
            try press(saved, "Read saved version", renderer: renderer)
            _ = try waitElement(saved.staticTexts.matching(identifier: "Observed from saved version file"), in: saved)
            _ = try unique(saved.staticTexts.matching(identifier: "2.3.4"), "fresh version observation is not the saved name")
            _ = try unique(saved.staticTexts.matching(identifier: "Build number 8"), "fresh version observation is not the saved build")
            try fixture.assertUnchanged()
        }
        if includeImages {
            try stage("images-cancel") {
                try press(renderer, "Metadata", renderer: renderer)
                let picker = try waitElement(named(renderer, "Localized screenshot and image import"), in: renderer)
                try select(picker, label: "Listing platform", value: "Android", renderer: renderer)
                try select(picker, label: "Listing language / locale", value: "fr-FR", renderer: renderer)
                try select(picker, label: "Image slot / Apple device size", value: "Phone screenshots", renderer: renderer)
                try press(picker, "Choose image files…", renderer: renderer, failures: Self.imageFailures)
                let sheet = try nativeSheet(window, title: "Choose up to 10 public PNG or JPEG listing images")
                try click(sheet.buttons.matching(identifier: "Cancel"), "native image Cancel unavailable")
                try waitGone(sheet)
                _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Original image selection cancelled")), in: renderer,
                                    timeout: 48, failures: Self.imageFailures)
                try fixture.assertUnchanged()
            }
            try stage("images") {
                let picker = try waitElement(named(renderer, "Localized screenshot and image import"), in: renderer)
                try press(picker, "Choose image files…", renderer: renderer, failures: Self.imageFailures)
                let sheet = try nativeSheet(window, title: "Choose up to 10 public PNG or JPEG listing images")
                try goToFolder(sheet, path: fixture.sourcesPath)
                let first = try waitElement(controls(sheet, [.cell, .outlineRow, .tableRow, .icon], label: "01.png"), in: sheet, enabled: true)
                let second = try waitElement(controls(sheet, [.cell, .outlineRow, .tableRow, .icon], label: "02.png"), in: sheet, enabled: true)
                try require(first.isHittable && second.isHittable, "native file items are not actionable")
                first.click()
                XCUIElement.perform(withKeyModifiers: .command) { second.click() }
                try require(first.isSelected && second.isSelected, "native two-file selection was not observed")
                try nativeOpen(sheet)
                let review = try waitElement(named(renderer, "Original localized-image operation"), in: renderer)
                _ = try waitElement(review.buttons.matching(identifier: "Review exact copy choices"), in: review,
                                    enabled: true, timeout: 48, failures: Self.imageFailures)
                try expand(review, prefix: "Native capture metadata (2 sources; not image approval)", renderer: renderer)
                for file in ["01.png", "02.png"] {
                    try require(review.staticTexts.matching(identifier: file).count >= 1, "native captured image name missing")
                    try require(review.staticTexts.matching(identifier: "SHA256 " + fixture.digest("sources/" + file)).count >= 1,
                                "native captured source digest does not match the fixed original")
                }
                try require(review.staticTexts.matching(identifier: "PNG · 1 × 1 pixels").count >= 2, "actual complete PNG headers were not inspected")
                for path in LocalFixture.imageTargets {
                    try require(review.staticTexts.matching(identifier: String(path.dropFirst("project/".count))).count >= 1,
                                "exact public image destination missing")
                }
                _ = try unique(review.staticTexts.matching(NSPredicate(format: "title == %@", "Final lexical Store input order")), "final image order was not displayed")
                _ = try unique(review.staticTexts.matching(identifier:
                    "The core supplies this order for the resulting paths. It is not drag-and-drop order or a promise that a Store accepts the images."),
                    "image preview lost its explicit no-Store-assurance distinction")
                try fixture.assertUnchanged()
                try press(review, "Review exact copy choices", renderer: renderer, failures: Self.imageFailures)
                let consent = try waitElement(named(review, "Fresh local action confirmation"), in: review,
                                              timeout: 48, failures: Self.imageFailures)
                let apply = try unique(consent.buttons.matching(identifier: "Confirm local image copy"), "image Apply action is ambiguous")
                try require(!apply.isEnabled, "local image copy began enabled without current consent")
                let choice = try unique(consent.checkBoxes, "image copy acknowledgement is missing or ambiguous")
                try require((choice.value as? String) == "0" || (choice.value as? NSNumber)?.intValue == 0,
                            "local image copy consent started checked")
                try fixture.assertUnchanged()
                try reveal(choice, in: renderer); choice.click()
                try press(consent, "Confirm local image copy", renderer: renderer, failures: Self.imageFailures)
                _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Reviewed public images copied locally")), in: review,
                                    timeout: 48, failures: Self.imageFailures)
                try fixture.accept("images")
            }
        } else {
            print("MRK_NORMAL_PROJECT_IMAGES=not-selected;result=not-run")
        }
        try stage("readback-and-quit") {
            try fixture.assertUnchanged()
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "normal affirmative Quit unavailable")
            try completeNormalQuit(app)
            try fixture.assertUnchanged()
            try fixture.closeOriginals()
            ownedFixture = nil
        }
        // These markers remain conditional on original XCTest/xcodebuild exit0,
        // exactly one selected passing test and the independent native owners.
        try acceptFinalScenario()
        print("MRK_MACOS_NORMAL_PROJECT_UI=project-config-workflows-text-version\(includeImages ? "-images" : "");cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }

    // Standalone opt-in preservation/refusal case; not an added project-batch case.
    @MainActor func testSyntheticProjectManagedWorkflowRefusal() throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300)
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("workflow-refusal-launch") { launched = try launchForJourney() }
        guard let (app, window, renderer) = launched else { throw Refusal.condition("ordinary launch returned no original") }
        let fixture = LocalFixture()
        ownedFixture = fixture
        try stage("workflow-refusal-fixture") { try fixture.prepare(.workflowRefusal) }

        @MainActor func noApplyControls() throws {
            let actions = ["Confirm reviewed local files", "Review unchanged confirmation",
                           "Apply already requested", "Apply reviewed local files", "Confirm unchanged plan"]
            try require(renderer.buttons.matching(NSPredicate(format: "label IN %@", actions)).count == 0,
                        "a refused workflow bundle exposed Apply authority")
            for title in ["Apply this four-caller bundle?", "Confirm four unchanged callers?"] {
                try require(renderer.dialogs.matching(identifier: title).count == 0,
                            "a refused workflow bundle exposed a confirmation dialog")
            }
            try require(renderer.checkBoxes.matching(NSPredicate(
                format: "label BEGINSWITH %@", "I reviewed all four paths and complete before/after text.")).count == 0,
                "a refused workflow bundle exposed a confirmation checkbox")
        }

        try stage("workflow-refusal-project-open") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(sheet, path: fixture.projectPath)
            try nativeOpen(sheet)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "selected project path is not exact")
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)
            try fixture.assertUnchanged()
        }
        try stage("workflow-refusal-preview") {
            try press(renderer, "GitHub", renderer: renderer)
            try replace(field(renderer, "Toolkit repository"), with: "Example/mobile-release-kit", renderer: renderer)
            try replace(field(renderer, "Full toolkit commit"), with: String(repeating: "a", count: 40), renderer: renderer)
            let comparison = try unique(renderer.checkBoxes.matching(identifier: "Use a caller-supplied summary — no files are read"),
                                        "optional comparison control is unavailable")
            try require((comparison.value as? String) == "0" || (comparison.value as? NSNumber)?.intValue == 0,
                        "passive supplied comparison unexpectedly enabled")
            try press(renderer, "Preview GitHub setup", renderer: renderer)
            let proposal = try waitElement(named(renderer, "Read-only GitHub setup proposal"), in: renderer,
                                          failures: Self.workflowFailures)
            _ = try waitElement(proposal.staticTexts.matching(NSPredicate(format: "title == %@", "Four read-only workflow previews")), in: proposal)
            for path in LocalFixture.callers {
                let shownPath = String(path.dropFirst("project/".count))
                try expand(proposal, prefix: shownPath, renderer: renderer)
                try displayed(proposal, label: "Read-only proposed content for " + shownPath,
                              equals: fixture.text(path, stage: "workflows"))
            }
            try noApplyControls()
            try fixture.assertUnchanged()
        }
        let review = try waitElement(named(renderer, "Local GitHub workflow files"), in: renderer)
        // Only this exact final conflict is expected here. The shared failure
        // list and every other workflow journey retain their refusal behavior.
        let refusalFailures = Self.workflowFailures.filter { $0 != "Local workflow bundle refused" }
        @MainActor func refusedOutcome() throws {
            try require(review.staticTexts.matching(NSPredicate(format: "label IN %@", refusalFailures)).count == 0,
                        "another workflow failure accompanied the expected refusal")
            _ = try unique(review.staticTexts.matching(NSPredicate(format: "title == %@", "Local workflow bundle refused")),
                           "the final original workflow refusal is missing or ambiguous")
            _ = try unique(review.staticTexts.matching(identifier: "existing_workflow_differs"),
                           "the final refusal is not the exact customized-caller conflict")
            let texts = review.staticTexts.allElementsBoundByIndex
            try require(!texts.isEmpty && texts.count <= 128
                && texts.allSatisfy { $0.label.utf8.count <= 4096 }, "workflow refusal presentation exceeds its bound")
            let labels = texts.map { $0.label.trimmingCharacters(in: .whitespacesAndNewlines) }
            let headings = labels.indices.filter { labels[$0] == "Observed differing callers · no Apply token" }
            let endings = labels.indices.filter {
                labels[$0] == "Only summaries actually obtained by the original capture are shown. Existing YAML is not exposed; no subset, force or overwrite option is available."
            }
            try require(headings.count == 1 && endings.count == 1 && headings[0] < endings[0],
                        "the original no-token conflict summary is missing or ambiguous")
            // The shipped number uses toLocaleString(): bind the hosted grouped
            // presentation, not the unformatted integer or unrelated byte labels.
            try require(Array(labels[(headings[0] + 1)..<endings[0]]) == [
                "candidate", "2,368 observed bytes",
                "cb50a58a62167a9e25da9eeb42a2c2d448f47445515e9fc291d3a23543762933"
            ], "the refused bundle did not report exactly the customized candidate")
            try require(!labels.contains { $0.contains("# MRK synthetic user customization; preserve exactly.") },
                        "the refusal exposed customized original YAML")
            let facts = try waitElement(named(review, "Independent native workflow outcome facts"), in: review,
                                        failures: refusalFailures)
            let factTexts = facts.staticTexts.allElementsBoundByIndex
            try require(factTexts.count == 8 && factTexts.allSatisfy { $0.label.utf8.count <= 64 },
                        "the four named native workflow outcome pairs are missing")
            let pairs = factTexts.map { $0.label.trimmingCharacters(in: .whitespacesAndNewlines) }
            try require(pairs == ["Transaction effect", "not_started", "Journal", "not_created",
                                  "Core resources", "settled", "Native finality", "settled"],
                        "the named original effect/journal/resource/finality facts are not settled refusal")
            try noApplyControls()
        }
        try stage("workflow-refusal-native-review") {
            try press(review, "Review local workflow files", renderer: renderer, failures: Self.workflowFailures)
            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Local workflow bundle refused")),
                                in: review, timeout: 48, failures: refusalFailures)
            try refusedOutcome()
            // All 15 original leaves retain exact bytes AND full StatFacts.
            // Closed child rosters also prove both other managed paths/control names absent.
            try fixture.assertUnchanged()
        }
        try stage("workflow-refusal-readback-and-quit") {
            try refusedOutcome()
            try fixture.assertUnchanged()
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "normal affirmative Quit unavailable")
            try completeNormalQuit(app)
            try fixture.assertUnchanged()
            try fixture.closeOriginals()
            ownedFixture = nil
        }
        try acceptFinalScenario()
        print("MRK_MACOS_NORMAL_WORKFLOW_REFUSAL_UI=ordinary-preview-customized-candidate-whole-bundle-refused-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }

    // Ordinary saved offline checks and empty project-recovery inspection only.
    // This block reuses the ordinary app/fixture/helpers. It is not a producer of
    // recovery records, an alternate invocation route or native finality evidence.
    @MainActor private func savedOperationComplete(_ panel: XCUIElement) throws {
        let texts = panel.staticTexts.allElementsBoundByIndex
        try require(!texts.isEmpty && texts.count <= 512, "saved-operation presentation exceeds its finite bound")
        try require(texts.allSatisfy { $0.label.utf8.count <= 4096 }, "saved-operation text exceeds its finite bound")
        let labels = texts.map { $0.label.trimmingCharacters(in: .whitespacesAndNewlines) }
        let anchors = labels.indices.filter { labels[$0].hasPrefix("Outcome:") }
        try require(anchors.count == 1, "original saved-operation outcome is missing or ambiguous")
        let start = anchors[0]
        // WebKit can expose the shipped <strong> label and following value as
        // separate static texts or one text. Admit only those two exact shapes.
        if labels[start] == "Outcome:" {
            try require(start + 1 < labels.count && labels[start + 1] == "complete",
                        "the original saved-operation outcome is not complete")
        } else {
            try require(labels[start] == "Outcome: complete", "the original saved-operation outcome is not complete")
        }
        _ = try unique(panel.staticTexts.matching(identifier: "Original operation settled"),
                       "the original saved-operation projection is not settled")
    }

    @MainActor private func savedOfflineCounts(_ report: XCUIElement) throws -> [String: Int] {
        let texts = report.staticTexts.allElementsBoundByIndex
        try require(!texts.isEmpty && texts.count <= 512, "offline report exceeds its finite presentation bound")
        try require(texts.allSatisfy { $0.label.utf8.count <= 4096 }, "offline report text exceeds its finite bound")
        let labels = texts.map { $0.label.trimmingCharacters(in: .whitespacesAndNewlines) }
        let statuses = ["PASS", "FAIL", "MISSING", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE"]
        let starts = labels.indices.filter { start in
            start + statuses.count * 2 <= labels.count
                && statuses.enumerated().allSatisfy { labels[start + $0.offset * 2] == $0.element }
        }
        try require(starts.count == 1, "the nine original status-count rows are missing or ambiguous")
        let start = starts[0]
        var counts: [String: Int] = [:]
        for (offset, status) in statuses.enumerated() {
            let value = labels[start + offset * 2 + 1]
            guard let count = Int(value), (0...128).contains(count), value == String(count) else {
                throw Refusal.condition("the small fixed fixture returned a noncanonical or unbounded count")
            }
            counts[status] = count
        }
        let total = counts.values.reduce(0, +)
        try require((1...128).contains(total) && counts["MISSING", default: 0] >= 2 && counts["SKIP", default: 0] >= 1,
                    "the fixture's missing module/wrapper and early-exit findings were not retained")
        let summary = "\(total) total findings · \(total) included in the returned list · 0 omitted from that list. Counts below include every reported finding."
        _ = try unique(report.staticTexts.matching(identifier: summary), "original offline count totals or omission state differ")
        for label in ["Android module configuration.", "Android Gradle wrapper policy.", "Core early-exit or remaining-check policy."] {
            _ = try unique(report.staticTexts.matching(identifier: label), "the expected negative-report finding is missing or repeated")
        }
        return counts
    }

    @MainActor func testSyntheticProjectSavedOfflineChecks() throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300)
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("offline-launch") { launched = try launchForJourney() }
        guard let (app, window, renderer) = launched else { throw Refusal.condition("ordinary offline launch returned no original") }
        let fixture = LocalFixture()
        ownedFixture = fixture
        try stage("offline-fixture") { try fixture.prepare() }
        try stage("offline-project-open") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(sheet, path: fixture.projectPath)
            try nativeOpen(sheet)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "offline project path is not exact")
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)
            try fixture.assertUnchanged()
        }
        let failures = ["No new offline-check outcome was confirmed", "Original cleanup unknown"]
        let unconfirmed = "The original command acknowledgement is unconfirmed. Do not repeat Start. A status observation can help cancel or settle that original operation, but cannot create consent."
        let historical = "This is retained original-operation data, not permission for the current editor or project context."
        var selected: XCUIElement?
        try stage("offline-review-and-start") {
            try press(renderer, "Releases", renderer: renderer)
            let panel = try waitElement(named(renderer, "Review the saved inputs and project-code effects")
                .containing(.button, identifier: "Refresh saved configuration observation"), in: renderer)
            selected = panel
            try require(named(panel, "Saved offline check findings").count == 0
                        && panel.staticTexts.matching(identifier: "Original operation settled").count == 0
                        && panel.buttons.matching(identifier: "Run saved offline checks").count == 0,
                        "a prior offline operation cannot supply this journey")
            try press(panel, "Refresh saved configuration observation", renderer: renderer, failures: failures, timeout: 10)
            try press(panel, "Review offline checks", renderer: renderer, failures: failures, timeout: 10)
            let consent = try waitElement(named(panel, "Confirm this saved offline-check intent"), in: panel,
                                          timeout: 10, failures: failures)
            let savedBytes = try fixture.text(LocalFixture.config).utf8.count
            let comparison = "Saved comparison: \(savedBytes) bytes. This review expires no later than five minutes after its original preparation; checking status never extends it."
            _ = try unique(consent.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", comparison)),
                           "the visible review is not bound to this fixture's exact saved-byte count")
            _ = try unique(panel.staticTexts.matching(identifier: "Awaiting explicit consent"), "offline intent is not awaiting consent")
            let run = try unique(consent.buttons.matching(identifier: "Run saved offline checks"), "offline Run is ambiguous")
            let acknowledgement = try unique(consent.checkBoxes, "offline acknowledgement is missing or ambiguous")
            try require(!run.isEnabled, "offline Run began enabled before acknowledgement")
            try require((acknowledgement.value as? String) == "0" || (acknowledgement.value as? NSNumber)?.intValue == 0,
                        "offline acknowledgement began checked")
            try require(named(panel, "Saved offline check findings").count == 0, "review alone produced an offline report")
            try fixture.assertUnchanged()
            try reveal(acknowledgement, in: renderer)
            acknowledgement.click()
            let start = try waitElement(consent.buttons.matching(identifier: "Run saved offline checks"), in: panel,
                                        enabled: true, timeout: try remaining(5), failures: failures)
            try require((acknowledgement.value as? String) == "1" || (acknowledgement.value as? NSNumber)?.intValue == 1,
                        "the exact offline acknowledgement was not retained")
            try reveal(start, in: renderer)
            try fixture.assertUnchanged()
            start.click() // The sole Start; the existing native1800/1810 clocks are unchanged.
        }
        guard let panel = selected else { throw Refusal.condition("original offline section is missing") }
        var missing = 0, skipped = 0
        try stage("offline-original-report") {
            // A transient unconfirmed acknowledgement is normal while awaiting
            // the original reply. It cannot be present in the accepted result.
            _ = try waitElement(panel.staticTexts.matching(identifier: "Original operation settled"), in: panel,
                                timeout: 90, failures: failures)
            try savedOperationComplete(panel)
            _ = try unique(panel.staticTexts.matching(identifier:
                "No lifecycle failure has been reported. Individual findings retain their own core status."),
                "offline operation did not settle without a lifecycle failure")
            let report = try unique(named(panel, "Saved offline check findings"), "the original offline report is missing or ambiguous")
            _ = try unique(report.staticTexts.matching(NSPredicate(format: "title == %@", "Returned offline-check report")), "returned offline report heading is missing")
            _ = try unique(report.staticTexts.matching(identifier: "This invocation only"), "offline report is not current to this invocation")
            _ = try unique(report.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "Complete is not PASS or release readiness.")),
                           "offline completion was misrepresented as readiness")
            for label in ["Offline selects the core checking mode. It is not network isolation or a sandbox.",
                          "Core-managed builds were disabled; configured checks can still perform their own builds.",
                          "Release readiness was not assessed. A returned report is not a release candidate or publication authority."] {
                _ = try unique(report.staticTexts.matching(identifier: label), "offline report lost a required scope limit")
            }
            let counts = try savedOfflineCounts(report)
            missing = counts["MISSING", default: 0]; skipped = counts["SKIP", default: 0]
            try require(panel.staticTexts.matching(identifier: unconfirmed).count == 0
                        && panel.staticTexts.matching(identifier: historical).count == 0
                        && report.staticTexts.matching(identifier: "Historical / stale context").count == 0
                        && panel.staticTexts.matching(NSPredicate(format: "label IN %@", failures)).count == 0
                        && named(panel, "Confirm this saved offline-check intent").count == 0
                        && panel.buttons.matching(identifier: "Run saved offline checks").count == 0,
                        "original offline report remains unconfirmed, stale, failed or rearmed")
            try fixture.assertUnchanged()
            try savedOperationComplete(panel)
            _ = try unique(report.staticTexts.matching(identifier: "This invocation only"), "offline report changed during readback")
        }
        try stage("offline-readback-and-quit") {
            try require(missing >= 2 && skipped >= 1, "no actual negative offline report was observed")
            try fixture.assertUnchanged()
            try savedOperationComplete(panel)
            let report = try unique(named(panel, "Saved offline check findings"), "offline report disappeared before normal Quit")
            _ = try unique(report.staticTexts.matching(identifier: "This invocation only"),
                           "offline report ceased to be current before normal Quit")
            for label in [unconfirmed, historical] + failures {
                try require(panel.staticTexts.matching(identifier: label).count == 0, "offline state changed before normal Quit")
            }
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "normal offline Quit unavailable")
            try completeNormalQuit(app)
            try fixture.assertUnchanged()
            try fixture.closeOriginals()
            ownedFixture = nil
        }
        // The fixture has no configured checks/build wrapper. The shared core
        // still performs fixed Git queries; this is not zero-command evidence.
        try acceptFinalScenario()
        print("MRK_MACOS_NORMAL_OFFLINE_UI=ordinary-ui-observed-saved-offline-report-and-settled-projection;missing=\(missing);skipped=\(skipped);releaseReadiness=not-assessed;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }

    @MainActor func testSyntheticProjectEmptyBuildInputInspection() throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300)
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("recovery-idle-launch") { launched = try launchForJourney() }
        guard let (app, window, renderer) = launched else { throw Refusal.condition("ordinary empty-recovery launch returned no original") }
        let fixture = LocalFixture()
        ownedFixture = fixture
        try stage("recovery-idle-fixture") { try fixture.prepare() }
        try stage("recovery-idle-project-open") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(sheet, path: fixture.projectPath)
            try nativeOpen(sheet)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "recovery inspection project path is not exact")
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)
            try fixture.assertUnchanged()
        }
        let failures = ["No new recovery outcome was confirmed", "Original cleanup unknown"]
        let unconfirmed = "The original acknowledgement is unconfirmed. Do not repeat the recovery action. Check its original status; a status observation never creates consent."
        let historical = "This retained observation is historical; it is not recovery permission for the current context."
        var selected: XCUIElement?
        try stage("recovery-idle-inspect") {
            try press(renderer, "Recovery", renderer: renderer)
            let panel = try waitElement(named(renderer, "Inspect first, then review what can safely be recovered")
                .containing(.button, identifier: "Help: Project build-input recovery"), in: renderer)
            selected = panel
            try require(panel.staticTexts.matching(identifier: "No pending build-input record observed").count == 0
                        && panel.staticTexts.matching(identifier: "Original operation settled").count == 0,
                        "a prior recovery inspection cannot supply this journey")
            let review = try unique(panel.buttons.matching(identifier: "Review recovery attempt"), "recovery Review is ambiguous")
            try require(!review.isEnabled && named(panel, "Confirm the exact build-input recovery attempt").count == 0,
                        "recovery mutation was offered before inspection")
            let inspect = try waitElement(panel.buttons.matching(identifier: "Inspect build-input state"), in: panel,
                                          enabled: true, timeout: 10, failures: failures)
            try reveal(inspect, in: renderer)
            try fixture.assertUnchanged()
            inspect.click() // This sole click authorizes the controller's inspect-only prepare/start, not Recover.
        }
        guard let panel = selected else { throw Refusal.condition("original project-recovery section is missing") }
        try stage("recovery-idle-original-report") {
            _ = try waitElement(panel.staticTexts.matching(identifier: "Original operation settled"), in: panel,
                                timeout: 135, failures: failures)
            try savedOperationComplete(panel)
            _ = try unique(panel.staticTexts.matching(NSPredicate(format: "title == %@", "No pending build-input record observed")),
                           "the actual original build-input inspection was not Idle")
            _ = try unique(panel.staticTexts.matching(identifier:
                "No lifecycle failure was reported. This operation concerns project build inputs only, not release readiness."),
                "the original inspection has a lifecycle failure")
            _ = try unique(panel.staticTexts.matching(identifier:
                "This is a build-input observation only. It does not mean the whole project, a previous file edit, signing account or Store release is clean."),
                "Idle inspection lost its limited absence-only meaning")
            let review = try unique(panel.buttons.matching(identifier: "Review recovery attempt"), "settled recovery Review is ambiguous")
            try require(!review.isEnabled && panel.checkBoxes.count == 0
                        && named(panel, "Confirm the exact build-input recovery attempt").count == 0
                        && panel.buttons.matching(identifier: "Recover reviewed build inputs").count == 0
                        && panel.buttons.matching(identifier: "Retire reviewed metadata").count == 0,
                        "Idle inspection enabled a recovery mutation or invented a recovery intent")
            for label in [unconfirmed, historical, "Recorded session:", "Reviewed build-input session recovered.",
                          "Reviewed terminal metadata retired.", "Pending build-input session", "Only terminal recovery metadata remains"] + failures {
                try require(panel.staticTexts.matching(identifier: label).count == 0,
                            "empty inspection contains unconfirmed, historical, pending or mutation-result data")
            }
            try fixture.assertUnchanged() // Includes the closed directory roster: no new hidden recovery metadata.
            try savedOperationComplete(panel)
        }
        try stage("recovery-idle-readback-and-quit") {
            try fixture.assertUnchanged()
            try savedOperationComplete(panel)
            _ = try unique(panel.staticTexts.matching(NSPredicate(format: "title == %@", "No pending build-input record observed")),
                           "original Idle inspection disappeared before normal Quit")
            for label in [unconfirmed, historical] + failures {
                try require(panel.staticTexts.matching(identifier: label).count == 0, "inspection state changed before normal Quit")
            }
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "normal empty-recovery Quit unavailable")
            try completeNormalQuit(app)
            try fixture.assertUnchanged()
            try fixture.closeOriginals()
            ownedFixture = nil
        }
        // No producer-finality receipt or pending journal is fabricated. A real
        // mutation-recovery journey still needs its own genuine eligible producer.
        try acceptFinalScenario()
        print("MRK_MACOS_NORMAL_RECOVERY_IDLE_UI=ordinary-ui-observed-empty-build-input-inspection-and-settled-projection;mutationRecovery=not-run;projectCleanliness=not-established;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }
    // End ordinary saved offline and empty recovery journeys.

    // One ordinary current diagnostics run, not full doctor or project-code execution.
    // No new observer, IPC, app hook or fixture bytes; queries use shipped AX content.
    @MainActor private func diagnosticsCoreReport(_ panel: XCUIElement) throws -> Int {
        let texts = panel.staticTexts.allElementsBoundByIndex
        try require(!texts.isEmpty && texts.count <= 256, "diagnostics accessible report exceeds its finite bound")
        let starts = texts.indices.filter { texts[$0].label == "Core outcome" }
        try require(starts.count == 1, "original core report anchor is missing or ambiguous")
        let start = starts[0]
        // Two presentation rows, then the nine immutable lifetime key/value rows.
        // Never filter away unknown rows or combine text from another AX subtree.
        try require(start + 22 <= texts.count, "original core report rows are incomplete")
        let rows = texts[start..<(start + 22)].map { $0.label }
        try require(rows.allSatisfy { $0.utf8.count <= 64 }, "core scalar presentation is not bounded")
        try require(rows[0] == "Core outcome" && rows[1] == "complete" && rows[2] == "Commands attempted",
                    "the actual core outcome is not a complete finite check")
        guard let attempts = Int(rows[3]), (1...4).contains(attempts), rows[3] == String(attempts) else {
            throw Refusal.condition("actual core command count is not one through four")
        }
        let expected = ["complete": "true", "fatal": "false", "contained": "true",
                        "commandDispatched": "true", "commands": String(attempts), "inputClosed": "true",
                        "handlersRestored": "true", "toolDescriptorsClosed": "true", "stopObserved": "none"]
        var observed: [String: String] = [:]
        for offset in stride(from: 4, to: 22, by: 2) {
            try require(expected[rows[offset]] != nil && observed[rows[offset]] == nil,
                        "original core lifetime row is foreign or repeated")
            observed[rows[offset]] = rows[offset + 1]
        }
        try require(observed == expected, "immutable core lifetime observations are incomplete")
        // These core facts are provisional on their own, never native finality.
        return attempts
    }

    @MainActor func testSyntheticProjectBuildToolDiagnostics() throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300)
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("diagnostics-launch") { launched = try launchForJourney() }
        guard let (app, window, renderer) = launched else { throw Refusal.condition("ordinary diagnostics launch returned no original") }
        let fixture = LocalFixture()
        ownedFixture = fixture
        try stage("diagnostics-fixture") { try fixture.prepare() }
        try stage("diagnostics-project-open") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(sheet, path: fixture.projectPath)
            try nativeOpen(sheet)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "diagnostics project path is not exact")
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)
            try fixture.assertUnchanged()
        }
        var panel: XCUIElement?
        try stage("diagnostics-context") {
            try press(renderer, "Environment", renderer: renderer)
            try select(renderer, label: "Release platform", value: "Android", renderer: renderer)
            try select(renderer, label: "Activity", value: "Build / archive", renderer: renderer)
            panel = try waitElement(named(renderer, "Observed build-tool checks")
                .containing(.button, identifier: "Check build tools"), in: renderer)
            try fixture.assertUnchanged()
        }
        guard let panel else { throw Refusal.condition("original diagnostics section is missing") }
        let failures = ["Original finality or status integrity is unknown", "Diagnostics status needs attention",
                        "Start reply unconfirmed", "Earlier / stale tool observations", "Phase: retained-unknown",
                        "Outcome: partial", "Outcome: failed", "Outcome: cancelled", "Outcome: timed-out", "Outcome: unavailable"]
        var commandsAttempted = 0
        try stage("diagnostics-original-report") {
            try require(panel.staticTexts.matching(identifier: "Tool observations from this run").count == 0
                        && panel.staticTexts.matching(identifier: "Earlier / stale tool observations").count == 0,
                        "a previous diagnostics report cannot supply this journey")
            // Availability admits only the click. It is not a tool/core result.
            let start = try waitElement(panel.buttons.matching(identifier: "Check build tools"), in: panel,
                                        enabled: true, timeout: 10, failures: failures)
            try reveal(start, in: renderer)
            guard let wholeDeadline = journeyDeadline else { throw Refusal.condition("original journey clock missing") }
            guard let clock = caseClock else { throw Refusal.condition("original case clock missing") }
            journeyDeadline = min(wholeDeadline, try clock.end(within: 15))
            defer { journeyDeadline = wholeDeadline } // Restore that SAME absolute outer deadline, never renew it.
            start.click() // The sole Start. Native work6/finality10 clocks are unchanged.
            let fresh = panel.staticTexts.matching(NSPredicate(format: "title == %@", "Tool observations from this run"))
            let phase = panel.staticTexts.matching(identifier: "Phase: settled")
            let outcome = panel.staticTexts.matching(identifier: "Outcome: complete")
            let finality = panel.staticTexts.matching(identifier: "Native finality: settled")
            let context = panel.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@ AND label ENDSWITH %@",
                "Android / build · draft ", " · core host macos"))
            let provenance = panel.staticTexts.matching(NSPredicate(format: "label ENDSWITH %@",
                " · acknowledged original Start. Receipt time is not a native deadline or a fresh probe."))
            let failed = panel.staticTexts.matching(NSPredicate(format: "label IN %@", failures))
            let targets: NSDictionary = ["fresh": fresh.element(boundBy: 0), "phase": phase.element(boundBy: 0),
                "outcome": outcome.element(boundBy: 0), "finality": finality.element(boundBy: 0),
                "context": context.element(boundBy: 0), "provenance": provenance.element(boundBy: 0),
                "failed": failed.element(boundBy: 0)]
            let ready = NSPredicate(format: "(fresh.exists == true AND phase.exists == true AND outcome.exists == true AND finality.exists == true AND context.exists == true AND provenance.exists == true) OR failed.exists == true")
            try require(XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: ready, object: targets)],
                                      timeout: try remaining(15)) == .completed && failed.count == 0,
                        "original diagnostics report or native settlement was not confirmed")
            for query in [fresh, phase, outcome, finality, context, provenance] {
                _ = try unique(query, "current acknowledged diagnostics report is missing or ambiguous")
            }
            let originalContext = context.element(boundBy: 0).label
            for label in ["macOS developer selection", "Git version", "Java runtime version", "Java compiler version"] {
                _ = try unique(panel.staticTexts.matching(NSPredicate(format: "title == %@", label)), "fixed Android diagnostics card is missing or repeated")
            }
            try require(panel.staticTexts.matching(identifier: "Xcode version and build").count == 0,
                        "this is the four-card Android roster, not an iOS Xcode qualification")
            try expand(panel, prefix: "Core resource observations — provisional, not native finality", renderer: renderer)
            _ = try waitElement(panel.staticTexts.matching(identifier: "Core outcome"), in: panel, failures: failures)
            commandsAttempted = try diagnosticsCoreReport(panel)
            _ = try remaining(15)
            try require(failed.count == 0 && context.element(boundBy: 0).label == originalContext,
                        "original report context changed during readback")
            for query in [fresh, phase, outcome, finality, provenance] {
                _ = try unique(query, "same original report did not remain current and settled")
            }
            // Missing/unselected/version-mismatch rows are observations, not failures.
            // No all-tool compatibility, full doctor, SDK or release-readiness claim.
            try fixture.assertUnchanged()
        }
        try stage("diagnostics-readback-and-quit") {
            try require((1...4).contains(commandsAttempted), "no original core command count was observed")
            try fixture.assertUnchanged()
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "normal diagnostics Quit unavailable")
            try completeNormalQuit(app)
            try fixture.assertUnchanged()
            try fixture.closeOriginals()
            ownedFixture = nil
        }
        // This marker alone is NOT a test-count, POSIX-exit or native-resource receipt.
        try acceptFinalScenario()
        print("MRK_MACOS_NORMAL_DIAGNOSTICS_UI=ordinary-ui-observed-original-diagnostics-report-and-settled-projection;commandsAttempted=\(commandsAttempted);cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }

    override func tearDown() async throws {
        var cleanupFailure: Error?
        do {
            try await MainActor.run {
                if let owner = originalLaunch { try owner.tearDown(normalQuit: normalQuitObserved) }
            }
        } catch { cleanupFailure = error }
        // The completed first original is retained, never stopped again and
        // never granted a fresh cleanup deadline after the active owner's five.
        do {
            try await MainActor.run {
                if let first = completedPersistenceLifetime {
                    guard first.normalQuit else { throw Refusal.condition("retained first normal Quit proof missing") }
                    try first.owner.recheckCompletedTerminal()
                }
            }
        } catch { if cleanupFailure == nil { cleanupFailure = error } }
        // Independent consuming closes even when app cleanup/clock is unknown.
        do { try await MainActor.run { try entryGateObservation?.closeOriginal() } }
        catch { if cleanupFailure == nil { cleanupFailure = error } }
        do { try await MainActor.run { try completedPersistenceLifetime?.gate.closeOriginal() } }
        catch { if cleanupFailure == nil { cleanupFailure = error } }
        // Never delete possibly live fixture/app state or seek a replacement owner.
        do {
            try await MainActor.run {
                if let fixture = ownedFixture { try fixture.closeOriginals(); ownedFixture = nil }
            }
        } catch { if cleanupFailure == nil { cleanupFailure = error } }
        do { try await super.tearDown() }
        catch { if cleanupFailure == nil { cleanupFailure = error } }
        if let cleanupFailure { throw cleanupFailure }
    }
}
