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
    @MainActor private var removalQuitObserved = false
    @MainActor private var removalChannel: RemovalChannel?
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
        init(seconds: TimeInterval, androidPositive: Bool = false, iosUnsigned: Bool = false) throws {
            let now = ProcessInfo.processInfo.systemUptime
            guard now.isFinite, now >= 0, !(androidPositive && iosUnsigned), ((androidPositive || iosUnsigned) ? seconds == 900 : (seconds == 60 || seconds == 300)),
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
        func healthy(cleanup: Bool = false) throws {
            guard !workClosed else { throw clock.fail("ordinary launch work is closed") }
            try callbackHealthy()
            if cleanup { _ = try payloadIdentity() } // Only the retained same original, never a lookup.
            _ = try clock.remaining(1, cleanup: cleanup)
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

    @MainActor private func beginCase(seconds: TimeInterval, androidPositive: Bool = false, iosUnsigned: Bool = false,
                                      removal: Bool = false) throws {
        try require(caseClock == nil && journeyDeadline == nil && originalLaunch == nil, "case deadline cannot be reset")
        try require((ProcessInfo.processInfo.environment["MRK_NORMAL_UI_REMOVAL_CHANNEL"] != nil) == removal
                    && (!removal || (seconds == 300 && !androidPositive && !iosUnsigned))
                    && !removalQuitObserved && removalChannel == nil,
                    "removal harness channel is exclusive to its fixed case")
        let clock = try CaseClock(seconds: seconds, androidPositive: androidPositive, iosUnsigned: iosUnsigned)
        caseClock = clock
        journeyDeadline = clock.deadline
    }

    @MainActor private func launchOrdinaryApplication() throws -> XCUIApplication {
        _ = try remaining(15)
        guard let clock = caseClock else { throw Refusal.condition("original case clock missing") }
        try require(originalLaunch == nil && entryGateObservation == nil && !normalQuitObserved && !removalQuitObserved
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
        // Six pre-check samples of this same guide, not a fallback or atomic snapshot.
        for property in ["label", "title"] {
            let kinds: [(String, XCUIElement.ElementType)] = [("any", .any), ("button", .button), ("checkBox", .checkBox)]
            for (kind, type) in kinds {
                _ = try remaining(1) // Same original owners/clock; a latched failure stops sampling.
                let count = guide.descendants(matching: type).matching(
                    NSPredicate(format: "%K BEGINSWITH %@", property, "Android upload keystore")).count
                print("MRK_MACOS_ENGINEERING_GUIDE_QUERY=v1;property=\(property);type=\(kind);matches=\(min(count, 5));exceedsFour=\(count > 4 ? 1 : 0);nonAtomic=1")
            }
        }
        // WebKit exposes aria-pressed buttons as Cocoa checkboxes, retaining toggle state.
        _ = try unique(guide.descendants(matching: .checkBox).matching(NSPredicate(format: "title BEGINSWITH %@", "Android upload keystore")),
                       "actual core Android guide is missing or repeated")
        let apple = try unique(guide.descendants(matching: .checkBox).matching(NSPredicate(format: "title BEGINSWITH %@", "Apple Distribution identity")),
                               "actual core Apple guide is missing or repeated")
        try reveal(apple, in: renderer)
        try require(apple.isEnabled && apple.isHittable, "actual core guide selection unavailable")
        apple.click() // Reference-only selection: no credential import or operation.
        _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Original Distribution P12")), in: renderer)
        _ = try unique(renderer.staticTexts.matching(identifier: "Reference guide · not a result"),
                       "guide was not explicitly reference-only")
        try engineeringNoFallback(renderer)
        try require(window.sheets.count == 0, "reference navigation opened an unexpected native operation")

        // Fresh native document only: a heading or event relay alone is not
        // Status invocation admission. An invoke failure remains visible until
        // a successful explicit checkStatus; equal-revision display is not a
        // separately correlated receipt for this button click.
        try click(renderer.buttons.matching(identifier: "Artifacts"), "engineering Artifacts navigation unavailable")
        _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Inspect selected artifact bytes")), in: renderer)
        let artifactStatusQuery = renderer.buttons.matching(identifier: "Check original artifact status")
        let artifactStatus = try waitElement(artifactStatusQuery, in: renderer, enabled: true,
                                             failures: ["No new artifact outcome confirmed"])
        try reveal(artifactStatus, in: renderer)
        try require(artifactStatus.isEnabled && artifactStatus.isHittable,
                    "engineering artifact Status read unavailable")
        artifactStatus.click() // Actual production bridge command; no fixture result.
        _ = try waitElement(artifactStatusQuery, in: renderer, enabled: true,
                            failures: ["No new artifact outcome confirmed"])
        let artifactAvailability = renderer.staticTexts.matching(NSPredicate(format: "title IN %@", [
            "This native document supports reviewing selected artifact bytes. Actual originals and runtime are rechecked before inspection.",
            "The required bundled runtime is not qualified for this document. Missing optional verification tools are a separate unavailable check."
        ]))
        _ = try waitElement(artifactAvailability, in: renderer,
                            failures: ["No new artifact outcome confirmed"])
        try require(renderer.staticTexts.matching(identifier: "No new artifact outcome confirmed").count == 0,
                    "engineering artifact Status invocation did not settle successfully")
        let chooseArtifact = try unique(renderer.buttons.matching(identifier: "Choose AAB"),
                                        "engineering artifact input control differs")
        let reviewArtifact = try unique(renderer.buttons.matching(identifier: "Review artifact inspection"),
                                        "engineering artifact review control differs")
        try require(!chooseArtifact.isEnabled && !reviewArtifact.isEnabled,
                    "engineering Status observation must not admit a project or inspection")
        try engineeringNoFallback(renderer)
        try require(window.sheets.count == 0, "engineering Status read opened an unexpected native operation")
        // This proves only a validated native Status in this fresh application,
        // not artifact inspection, every ACL entry, or signed/runtime readiness.

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


    // Two task-owned scheduling hints only. They never authenticate an installer,
    // peer, consent, exit status, payload, or a future successful close.
    @MainActor private final class RemovalChannel {
        private struct Directory {
            let fd: Int32
            let parent: Int?
            let name: String
            let identity: StatFacts
        }
        private let clock: CaseClock
        private let ordinary: Bool
        private var directories: [Directory] = []
        private var pendingDirectory: Int32?
        private var enumerationFD: Int32?
        private var leaf: Int32?
        private var correlation = ""
        private var markers: [String: StatFacts] = [:]
        private var entered = false
        private var closed = false
        init(clock: CaseClock, ordinary: Bool) { self.clock = clock; self.ordinary = ordinary }
        private func tick() throws { _ = try clock.remaining(1) }
        private func need(_ yes: Bool, _ reason: String) throws {
            guard yes else { throw clock.fail(reason) }
            try tick()
        }
        private func info(_ fd: Int32) throws -> StatFacts {
            try tick()
            var value = stat()
            try need(fstat(fd, &value) == 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC,
                     "removal channel held stat or descriptor refused")
            return StatFacts(value)
        }
        private func named(_ parent: Int32, _ name: String) throws -> StatFacts {
            try tick()
            var value = stat()
            try need(fstatat(parent, name, &value, AT_SYMLINK_NOFOLLOW) == 0,
                     "removal channel named stat failed")
            return StatFacts(value)
        }
        private func noAuxiliary(_ fd: Int32, _ expected: StatFacts) throws {
            try tick()
            guard let section = filesec_init() else { throw clock.fail("removal channel filesec allocation failed") }
            var failed: Error?
            do {
                try tick()
                var snapshot = stat(), owner: uid_t = 0, group: gid_t = 0, mode: mode_t = 0
                var present: Int32 = 0
                try need(fstatx_np(fd, &snapshot, section) == 0 && StatFacts(snapshot) == expected,
                         "removal channel ACL snapshot changed")
                try need(filesec_get_property(section, FILESEC_OWNER, &owner) == 0 && owner == expected.uid,
                         "removal channel ACL owner unavailable")
                try need(filesec_get_property(section, FILESEC_GROUP, &group) == 0 && group == expected.gid,
                         "removal channel ACL group unavailable")
                try need(filesec_get_property(section, FILESEC_MODE, &mode) == 0 && mode == expected.mode,
                         "removal channel ACL mode unavailable")
                try need(filesec_query_property(section, FILESEC_ACL, &present) == 0 && present == 0,
                         "removal channel requires an absent ACL")
                try need(flistxattr(fd, nil, 0, 0) == 0, "removal channel attributes refused")
                try need(info(fd) == expected, "removal channel auxiliary POST changed")
            } catch { failed = error }
            filesec_free(section) // Void consuming API, including every refusal path.
            if let failed { throw failed }
            try tick()
        }
        private func pathPost() throws {
            try need(!closed && !directories.isEmpty && directories.count <= 32,
                     "removal channel original path missing")
            for (index, directory) in directories.enumerated() {
                let actual = try info(directory.fd)
                try need(directory.identity.sameDirectory(actual), "removal channel path original changed")
                if let parent = directory.parent {
                    let current = try named(directories[parent].fd, directory.name)
                    try need(current.sameDirectory(actual), "removal channel path binding changed")
                } else {
                    var current = stat()
                    try need(lstat("/", &current) == 0 && StatFacts(current).sameDirectory(actual),
                             "removal channel root original changed")
                }
                if index >= directories.count - 2 {
                    try need(actual.mode == S_IFDIR | 0o700 && actual.uid == getuid()
                             && actual.gid == getgid() && actual.flags == 0,
                             "removal channel private directory protection refused")
                    try noAuxiliary(directory.fd, actual)
                }
            }
        }
        private func roster() throws -> Set<String> {
            try pathPost()
            guard let directory = directories.last else { throw clock.fail("removal channel directory missing") }
            try need(enumerationFD == nil, "removal channel enumeration already owned")
            let fd = openat(directory.fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if fd >= 0 { enumerationFD = fd }
            try need(fd >= 0, "removal channel enumeration open failed")
            guard let stream = fdopendir(fd) else { throw clock.fail("removal channel fdopendir failed") }
            enumerationFD = nil // Only closedir owns this original from now on.
            var names: Set<String> = [], failed: Error?
            do {
                var eof = false
                for _ in 0..<5 { // Two names + dot entries, then EOF; raw entries count.
                    try tick(); errno = 0
                    guard let entry = readdir(stream) else {
                        let code = errno
                        try need(code == 0, "removal channel readdir failed")
                        eof = true; break
                    }
                    let count = Int(entry.pointee.d_namlen)
                    try need((1...255).contains(count), "removal channel name length refused")
                    let bytes = withUnsafeBytes(of: entry.pointee.d_name) { Array($0.prefix(count + 1)) }
                    try need(bytes.count == count + 1 && bytes[count] == 0, "removal channel name terminator refused")
                    guard let name = String(bytes: bytes.prefix(count), encoding: .utf8) else {
                        throw clock.fail("removal channel name encoding refused")
                    }
                    if name == "." || name == ".." { continue }
                    try need((name == "launched" || (ordinary && name == "cancel-observed"))
                             && names.insert(name).inserted, "removal channel foreign or duplicate marker")
                }
                try need(eof, "removal channel roster bound exceeded")
            } catch { failed = error }
            let result = closedir(stream) // Consume once even if enumeration failed.
            if let failed { throw failed }
            try need(result == 0, "removal channel enumeration close unknown")
            try pathPost()
            return names
        }
        func open() throws {
            try need(!entered && !closed && getuid() != 0 && getuid() == geteuid() && getgid() == getegid(),
                     "removal channel requires one ordinary user admission")
            entered = true
            guard let path = ProcessInfo.processInfo.environment["MRK_NORMAL_UI_REMOVAL_CHANNEL"] else {
                throw clock.fail("removal channel not supplied by its original owner")
            }
            let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            try need(path.utf8.count <= 1024 && !path.utf8.contains(0) && parts.first == ""
                     && (4...32).contains(parts.count) && parts.dropFirst().allSatisfy {
                         !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255
                     } && parts[parts.count - 2] == "removal-ui-v1", "removal channel canonical path refused")
            let last = parts[parts.count - 1]
            try need(last.hasPrefix("r-") && last.utf8.count == 34, "removal channel correlation shape refused")
            correlation = String(last.dropFirst(2))
            try need(correlation.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
                     && correlation != String(repeating: "0", count: 32), "removal channel correlation refused")
            for index in parts.indices {
                try tick()
                let fd = index == 0
                    ? Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    : openat(directories[index - 1].fd, parts[index], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                if fd >= 0 { pendingDirectory = fd }
                try need(fd >= 0, "removal channel original directory open failed")
                let identity = try info(fd)
                try need(identity.mode & S_IFMT == S_IFDIR, "removal channel path is not a directory")
                directories.append(Directory(fd: fd, parent: index == 0 ? nil : index - 1,
                                             name: index == 0 ? "/" : parts[index], identity: identity))
                pendingDirectory = nil
            }
            try need(roster().isEmpty, "removal channel was not exclusively empty")
        }
        private func body(_ name: String) -> [UInt8] {
            Array(("mrk-removal-ui-v1\n" + correlation + "\n" + (ordinary ? "ordinary" : "abrupt") + "\n" + name + "\n").utf8)
        }
        private func readBack(_ name: String) throws -> StatFacts {
            guard let fd = leaf, let directory = directories.last else { throw clock.fail("removal channel leaf custody missing") }
            let expected = body(name), before = try info(fd)
            try need(expected.count <= 128 && before.mode == S_IFREG | 0o600 && before.uid == getuid()
                     && before.gid == getgid() && before.links == 1 && before.flags == 0
                     && before.bytes == expected.count, "removal channel marker shape refused")
            try need(named(directory.fd, name) == before, "removal channel marker named binding changed")
            try noAuxiliary(fd, before)
            var bytes = [UInt8](repeating: 0, count: 129)
            let readCount = bytes.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
            try need(readCount == expected.count && Array(bytes.prefix(expected.count)) == expected,
                     "removal channel marker body changed")
            var extra: UInt8 = 0
            try need(pread(fd, &extra, 1, off_t(expected.count)) == 0 && info(fd) == before
                     && named(directory.fd, name) == before, "removal channel marker EOF or POST changed")
            return before
        }
        private func closeLeaf() throws {
            if let fd = leaf {
                leaf = nil
                let result = Darwin.close(fd)
                try need(result == 0, "removal channel marker close unknown")
            }
        }
        func verify() throws {
            try need(roster() == Set(markers.keys), "removal channel roster changed")
            guard let directory = directories.last else { throw clock.fail("removal channel directory missing") }
            for name in markers.keys.sorted() {
                try need(leaf == nil, "removal channel marker already owned")
                let fd = openat(directory.fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                if fd >= 0 { leaf = fd }
                try need(fd >= 0, "removal channel marker reread failed")
                try need(readBack(name) == markers[name], "removal channel immutable marker replaced")
                try closeLeaf()
            }
            try pathPost()
        }
        func publish(_ name: String) throws {
            try need((name == "launched" && markers.isEmpty)
                     || (ordinary && name == "cancel-observed" && Set(markers.keys) == ["launched"]),
                     "removal channel marker order refused")
            try verify()
            guard let directory = directories.last else { throw clock.fail("removal channel directory missing") }
            let bytes = body(name)
            try need(leaf == nil && bytes.count <= 128, "removal channel writer admission refused")
            let fd = openat(directory.fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            if fd >= 0 { leaf = fd }
            try need(fd >= 0, "removal channel exclusive marker creation failed")
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            try need(count == bytes.count, "removal channel complete marker write failed")
            let identity = try readBack(name)
            try closeLeaf()
            markers[name] = identity
            try verify()
        }
        func finish() throws {
            try need(Set(markers.keys) == (ordinary ? ["launched", "cancel-observed"] : ["launched"]),
                     "removal channel final sequence incomplete")
            try verify()
            try closeOriginals()
            try tick()
        }
        func closeOriginals() throws {
            if closed { return }
            closed = true
            var first: Error?
            func consume(_ fd: Int32) {
                if Darwin.close(fd) != 0 && first == nil { first = clock.fail("removal channel consuming close unknown") }
            }
            if let fd = leaf { leaf = nil; consume(fd) }
            if let fd = enumerationFD { enumerationFD = nil; consume(fd) }
            if let fd = pendingDirectory { pendingDirectory = nil; consume(fd) }
            for directory in directories.reversed() { consume(directory.fd) }
            directories.removeAll()
            if let first { throw first }
        }
    }

    @MainActor private func removalSheet(_ window: XCUIElement) throws -> XCUIElement {
        try require(window.sheets.element(boundBy: 0).waitForExistence(timeout: try remaining(120)),
                    "authenticated removal sheet did not appear")
        let sheet = try unique(window.sheets, "removal sheet is ambiguous")
        _ = try unique(sheet.staticTexts.matching(identifier: "Quit and prepare to remove Mobile Release Kit?"),
                       "unexpected removal confirmation")
        try require(sheet.buttons.count == 2, "unexpected removal actions")
        _ = try unique(sheet.buttons.matching(identifier: "Cancel"), "removal Cancel is not unique")
        _ = try unique(sheet.buttons.matching(identifier: "Continue and Quit"), "removal Continue is not unique")
        return sheet
    }

    @MainActor func testInstalledRemovalCancelThenContinue() throws { try removalJourney(ordinary: true) }
    @MainActor func testInstalledRemovalContinueBeforeInterruption() throws { try removalJourney(ordinary: false) }

    @MainActor private func removalJourney(ordinary: Bool) throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300, removal: true)
        guard let clock = caseClock else { throw Refusal.condition("removal case clock missing") }
        let channel = RemovalChannel(clock: clock, ordinary: ordinary)
        removalChannel = channel // Retain before fallible path admission.
        try channel.open()
        _ = try admittedJourneyApplication(profile: .sameBuild)
        let app = try launchOrdinaryApplication()
        try require(app.wait(for: .runningForeground, timeout: try remaining(5)), "removal app not foreground")
        try require(app.windows.element(boundBy: 0).waitForExistence(timeout: try remaining(5)), "removal app window unavailable")
        let window = try unique(app.windows, "removal app window ambiguous")
        try require(window.isHittable, "removal app window not usable")
        let rendererQuery = window.webViews
        try require(rendererQuery.count <= 1, "removal renderer is initially ambiguous")
        try require(rendererQuery.element(boundBy: 0).waitForExistence(timeout: try remaining(5)),
                    "removal renderer did not become available")
        let renderer = try unique(rendererQuery, "removal renderer unavailable or ambiguous")
        try dashboard(renderer)
        guard let owner = originalLaunch, let gate = entryGateObservation else { throw clock.fail("removal UI original custody missing") }
        try owner.healthy(); try gate.probe(busy: true)
        try channel.publish("launched")
        if ordinary {
            let first = try removalSheet(window)
            try click(first.buttons.matching(identifier: "Cancel"), "genuine removal Cancel unavailable")
            let dismissed = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: first)
            try require(XCTWaiter.wait(for: [dismissed], timeout: try remaining(10)) == .completed,
                        "removal Cancel did not dismiss the original sheet")
            try owner.healthy(); try gate.probe(busy: true)
            try require(app.state == .runningForeground && window.exists, "removal Cancel did not preserve the same app")
            try click(renderer.buttons.matching(identifier: "Project settings"), "post-removal-Cancel settings unavailable")
            try require(renderer.staticTexts.matching(identifier: "A little clarity before the next release.")
                        .element(boundBy: 0).waitForExistence(timeout: try remaining(5)),
                        "post-removal-Cancel settings navigation did not complete")
            try click(renderer.buttons.matching(identifier: "Dashboard"), "post-removal-Cancel Dashboard unavailable")
            try dashboard(renderer)
            try channel.publish("cancel-observed")
        }
        let last = try removalSheet(window)
        try click(last.buttons.matching(identifier: "Continue and Quit"), "genuine removal Continue unavailable")
        let end = try clock.end(within: 120)
        try require(app.wait(for: .notRunning, timeout: try clock.remaining(120, before: end)), "removal did not stop its original app")
        try owner.observeNormalTermination(until: end) // Same retained original; no menu-Quit or gate-free implication.
        try require(app.state == .notRunning && !normalQuitObserved && !removalQuitObserved,
                    "removal terminal origin is not exclusive")
        try gate.closeOriginal() // Parent may still own M_EX. Do not probe lock-free here.
        try owner.acceptTerminal()
        try channel.finish()
        try owner.acceptTerminal(); _ = try remaining(1)
        removalQuitObserved = true
        print("MRK_MACOS_REMOVAL_UI=v1;case=\(ordinary ? "ordinary" : "abrupt");cancelObserved=\(ordinary ? 1 : 0);continueObserved=1;originalTerminated=1;gateClosed=1;gateFree=unqualified;normalQuit=0;channelClosed=1")
        // Pending until actual original xcodebuild success, returned result and all outer joins.
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
        enum Profile: Equatable { case projectEdits, projectFields, persistentCredentials, workflowRefusal, savedVersionRecovery, releaseEvidence, androidSignedBuild, iosUnsignedArchive }
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
        // Public saved-document DATA only. No referenced artifact is materialized.
        // Decoding/pin/census checks precede all task-owned fixture creation.
        static let releaseEvidenceDocuments: [(String, String, Int, String)] = [
            ("evidence/candidate-manifest.json", "ewogICJzY2hlbWFWZXJzaW9uIjogMiwKICAidG9vbGluZyI6IHsKICAgICJ2ZXJzaW9uIjogIjAuMi4wIiwKICAgICJjb21taXQiOiAiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIKICB9LAogICJyZXBvc2l0b3J5IjogewogICAgImZ1bGxOYW1lIjogImV4YW1wbGUvbW9iaWxlLWFwcCIsCiAgICAiaWQiOiAiMTAwMDAwMDAwIgogIH0sCiAgInNvdXJjZSI6IHsKICAgICJjb21taXQiOiAiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsCiAgICAidHJlZSI6ICIzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzIiwKICAgICJyZWYiOiAicmVmcy9oZWFkcy9tYWluIgogIH0sCiAgImNvbmZpZ3VyYXRpb24iOiB7CiAgICAicGF0aCI6ICJyZWxlYXNlL21vYmlsZS1yZWxlYXNlLmpzb24iLAogICAgInNoYTI1NiI6ICI0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0IiwKICAgICJtZXRhZGF0YVNoYTI1NiI6ICI1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1IgogIH0sCiAgInZlcnNpb24iOiB7CiAgICAibWFya2V0aW5nIjogIjEuMi4zIiwKICAgICJidWlsZCI6IDQyCiAgfSwKICAicGxhdGZvcm1zIjogewogICAgImFuZHJvaWQiOiB7CiAgICAgICJhcHBsaWNhdGlvbklkIjogImNvbS5leGFtcGxlLnJlYWRlciIKICAgIH0KICB9LAogICJhcnRpZmFjdHMiOiBbCiAgICB7CiAgICAgICJsb2dpY2FsTmFtZSI6ICJhbmRyb2lkLWFhYiIsCiAgICAgICJwbGF0Zm9ybSI6ICJhbmRyb2lkIiwKICAgICAgImtpbmQiOiAiYWFiIiwKICAgICAgImZpbGVOYW1lIjogInJlYWRlci0xLjIuMy00Mi5hYWIiLAogICAgICAic2l6ZSI6IDEyMzQ1Njc4LAogICAgICAic2hhMjU2IjogIjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYiLAogICAgICAiYXJjaGl0ZWN0dXJlcyI6IFsKICAgICAgICAiYXJtNjQtdjhhIiwKICAgICAgICAieDg2XzY0IgogICAgICBdCiAgICB9LAogICAgewogICAgICAibG9naWNhbE5hbWUiOiAic3RvcmUtbWV0YWRhdGEiLAogICAgICAicGxhdGZvcm0iOiAic2hhcmVkIiwKICAgICAgImtpbmQiOiAibWV0YWRhdGEiLAogICAgICAiZmlsZU5hbWUiOiAic3RvcmUtbWV0YWRhdGEtMS4yLjMtNDIuemlwIiwKICAgICAgInNpemUiOiAzNDU2NywKICAgICAgInNoYTI1NiI6ICI1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1IiwKICAgICAgImFyY2hpdGVjdHVyZXMiOiBbXQogICAgfSwKICAgIHsKICAgICAgImxvZ2ljYWxOYW1lIjogInZhbGlkYXRpb24tcmVwb3J0IiwKICAgICAgInBsYXRmb3JtIjogInNoYXJlZCIsCiAgICAgICJraW5kIjogInZhbGlkYXRpb24tcmVwb3J0IiwKICAgICAgImZpbGVOYW1lIjogInZhbGlkYXRpb24tcmVwb3J0LTEuMi4zLTQyLmpzb24iLAogICAgICAic2l6ZSI6IDIzNDUsCiAgICAgICJzaGEyNTYiOiAiNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3NyIsCiAgICAgICJhcmNoaXRlY3R1cmVzIjogW10KICAgIH0KICBdLAogICJzaWduaW5nIjogWwogICAgewogICAgICAicGxhdGZvcm0iOiAiYW5kcm9pZCIsCiAgICAgICJraW5kIjogImFuZHJvaWQtdXBsb2FkIiwKICAgICAgImNlcnRpZmljYXRlU2hhMjU2IjogImFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEiCiAgICB9CiAgXSwKICAic3RvcmVSZWNlaXB0cyI6IFsKICAgIHsKICAgICAgInByb3ZpZGVyIjogImdvb2dsZS1wbGF5IiwKICAgICAgImFwcGxpY2F0aW9uSWQiOiAiY29tLmV4YW1wbGUucmVhZGVyIiwKICAgICAgInN0b3JlQnVpbGRJZCI6ICI0MiIsCiAgICAgICJtYXJrZXRpbmdWZXJzaW9uIjogIjEuMi4zIiwKICAgICAgImJ1aWxkIjogNDIsCiAgICAgICJjaGFubmVsIjogImludGVybmFsIiwKICAgICAgInN0YXRlIjogImF2YWlsYWJsZS10by10ZXN0ZXJzIiwKICAgICAgIm9ic2VydmVkQXQiOiAiMjAyNi0wMS0wMVQwMDowMDowMFoiCiAgICB9CiAgXSwKICAiY3JlYXRlZEF0IjogIjIwMjYtMDEtMDFUMDA6MDA6MDBaIiwKICAiZG9jdW1lbnRUeXBlIjogImNhbmRpZGF0ZS1tYW5pZmVzdCIsCiAgIm9wZXJhdGlvbkludGVudFNoYTI1NiI6ICIyNGI5ODI5YzdlZTU4ZjU3OWVjODJmMTZjYzQ2OWQ1YjI3NjQxMDU0YmFlY2U1ODFiZWM1ODhjYjM3MGY4YjI5IiwKICAiYXV0aG9yaXplZEJ5IjogewogICAgIndvcmtmbG93IjogIk1vYmlsZSBjYW5kaWRhdGUiLAogICAgImNhbGxlclBhdGgiOiAiLmdpdGh1Yi93b3JrZmxvd3MvbW9iaWxlLWNhbmRpZGF0ZS55bWwiLAogICAgInJldXNhYmxlUmVwb3NpdG9yeSI6ICJleGFtcGxlL21vYmlsZS1yZWxlYXNlLWtpdCIsCiAgICAicmV1c2FibGVQYXRoIjogIi5naXRodWIvd29ya2Zsb3dzL3JldXNhYmxlLWNhbmRpZGF0ZS55bWwiLAogICAgInJldXNhYmxlQ29tbWl0IjogIjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLAogICAgInJ1bklkIjogIjEwMDAwMDAwMDAiLAogICAgImF0dGVtcHQiOiAxLAogICAgImhlYWRTaGEiOiAiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsCiAgICAicmVmIjogInJlZnMvaGVhZHMvbWFpbiIsCiAgICAiZXZlbnQiOiAid29ya2Zsb3dfZGlzcGF0Y2giCiAgfSwKICAiZXhlY3V0ZWRCeSI6IHsKICAgICJ3b3JrZmxvdyI6ICJNb2JpbGUgY2FuZGlkYXRlIiwKICAgICJjYWxsZXJQYXRoIjogIi5naXRodWIvd29ya2Zsb3dzL21vYmlsZS1jYW5kaWRhdGUueW1sIiwKICAgICJyZXVzYWJsZVJlcG9zaXRvcnkiOiAiZXhhbXBsZS9tb2JpbGUtcmVsZWFzZS1raXQiLAogICAgInJldXNhYmxlUGF0aCI6ICIuZ2l0aHViL3dvcmtmbG93cy9yZXVzYWJsZS1jYW5kaWRhdGUueW1sIiwKICAgICJyZXVzYWJsZUNvbW1pdCI6ICIxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwKICAgICJydW5JZCI6ICIxMDAwMDAwMDAwIiwKICAgICJhdHRlbXB0IjogMSwKICAgICJoZWFkU2hhIjogIjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLAogICAgInJlZiI6ICJyZWZzL2hlYWRzL21haW4iLAogICAgImV2ZW50IjogIndvcmtmbG93X2Rpc3BhdGNoIgogIH0sCiAgInByb2R1Y2VkQnkiOiB7CiAgICAid29ya2Zsb3ciOiAiTW9iaWxlIGNhbmRpZGF0ZSIsCiAgICAiY2FsbGVyUGF0aCI6ICIuZ2l0aHViL3dvcmtmbG93cy9tb2JpbGUtY2FuZGlkYXRlLnltbCIsCiAgICAicmV1c2FibGVSZXBvc2l0b3J5IjogImV4YW1wbGUvbW9iaWxlLXJlbGVhc2Uta2l0IiwKICAgICJyZXVzYWJsZVBhdGgiOiAiLmdpdGh1Yi93b3JrZmxvd3MvcmV1c2FibGUtY2FuZGlkYXRlLnltbCIsCiAgICAicmV1c2FibGVDb21taXQiOiAiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIsCiAgICAicnVuSWQiOiAiMTAwMDAwMDAwMCIsCiAgICAiYXR0ZW1wdCI6IDEsCiAgICAiaGVhZFNoYSI6ICIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyIiwKICAgICJyZWYiOiAicmVmcy9oZWFkcy9tYWluIiwKICAgICJldmVudCI6ICJ3b3JrZmxvd19kaXNwYXRjaCIKICB9LAogICJpbnRlZ3JpdHkiOiB7CiAgICAiYWxnb3JpdGhtIjogInNoYTI1NiIsCiAgICAic2hhMjU2IjogIjE3N2I1ZjNlOTJiM2IwMmI5OTQ4OWJiNmU3YTZhYWNhMTgzYjE2YzM3MTIxODcxNWY3OTg3MmUxNTk3ZThjMTYiCiAgfQp9Cg==", 3907, "285685846ac73e215aacc77436884e42f3e973a105dc5e40f1add0a020f2e06d"),
            ("evidence/candidate-receipt.json", "ewogICJzY2hlbWFWZXJzaW9uIjogMywKICAic3RhZ2UiOiAiY2FuZGlkYXRlIiwKICAiY2FuZGlkYXRlTWFuaWZlc3RTaGEyNTYiOiAiMTc3YjVmM2U5MmIzYjAyYjk5NDg5YmI2ZTdhNmFhY2ExODNiMTZjMzcxMjE4NzE1Zjc5ODcyZTE1OTdlOGMxNiIsCiAgInRvb2xpbmciOiB7CiAgICAidmVyc2lvbiI6ICIwLjIuMCIsCiAgICAiY29tbWl0IjogIjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiCiAgfSwKICAicmVwb3NpdG9yeSI6IHsKICAgICJmdWxsTmFtZSI6ICJleGFtcGxlL21vYmlsZS1hcHAiLAogICAgImlkIjogIjEwMDAwMDAwMCIKICB9LAogICJzb3VyY2UiOiB7CiAgICAiY29tbWl0IjogIjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLAogICAgInRyZWUiOiAiMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMyIKICB9LAogICJwbGF0Zm9ybSI6ICJhbmRyb2lkIiwKICAicHJvdmlkZXIiOiAiZ29vZ2xlLXBsYXkiLAogICJhcHBsaWNhdGlvbklkIjogImNvbS5leGFtcGxlLnJlYWRlciIsCiAgInZlcnNpb24iOiB7CiAgICAibWFya2V0aW5nIjogIjEuMi4zIiwKICAgICJidWlsZCI6IDQyCiAgfSwKICAic3RvcmVCdWlsZElkIjogIjQyIiwKICAib3BlcmF0aW9uIjogInVwbG9hZGVkIiwKICAiZGVzdGluYXRpb24iOiB7CiAgICAiY2hhbm5lbCI6ICJpbnRlcm5hbCIsCiAgICAicmVsZWFzZVN0YXR1cyI6ICJjb21wbGV0ZWQiCiAgfSwKICAicmVhZGJhY2siOiB7CiAgICAic3RhdGUiOiAiYXZhaWxhYmxlLXRvLXRlc3RlcnMiLAogICAgIm9ic2VydmVkQXQiOiAiMjAyNi0wMS0wMVQwMDowMDowMFoiCiAgfSwKICAiY3JlYXRlZEF0IjogIjIwMjYtMDEtMDFUMDA6MDA6MDBaIiwKICAib3V0Y29tZSI6ICJtdXRhdGVkIiwKICAic3RvcmVTdGF0ZSI6IHsKICAgICJjYW5vbmljYWxpemF0aW9uIjogIm1yay1wbGF5LXRyYWNrLXN0YXRlLXYyIiwKICAgICJtb2RlIjogIm11dGF0aW9uIiwKICAgICJtdXRhdGlvbkVkaXRJZCI6ICJtdXRhdGlvbi1lZGl0IiwKICAgICJyZWFkYmFja0VkaXRJZCI6ICJyZWFkYmFjay1lZGl0IiwKICAgICJkZXN0aW5hdGlvbkJlZm9yZVNoYTI1NiI6ICJhZGEwMTEzNDliNzUwNTI2ZTFkNGE3YWMxNzkxMzM4NGQxNGZlYTljMGQ2N2YyYzQ5ZTRkZGI3YWQ4MDE0NzVkIiwKICAgICJkZXN0aW5hdGlvbkV4cGVjdGVkU2hhMjU2IjogIjBjMmFlNGE3MDUxMGViOWUxZGIxMWY5MjJjOTgzYmRkNWZiMjgxMTZiNDZiNjAyNjE0ZGIwMTdkZDM2MWY4NWQiLAogICAgImRlc3RpbmF0aW9uQ29tbWl0dGVkU2hhMjU2IjogIjBjMmFlNGE3MDUxMGViOWUxZGIxMWY5MjJjOTgzYmRkNWZiMjgxMTZiNDZiNjAyNjE0ZGIwMTdkZDM2MWY4NWQiLAogICAgInVucmVsYXRlZEJlZm9yZVNoYTI1NiI6ICJkMjlkZjRjMzkxMDg0ODk4YzllMTIzNTg0OWYxMTE0ZWQ5YjE3NGEzMzVhNzIyOTlhODBmYTdkMWEyODIyYTM2IiwKICAgICJ1bnJlbGF0ZWRDb21taXR0ZWRTaGEyNTYiOiAiZDI5ZGY0YzM5MTA4NDg5OGM5ZTEyMzU4NDlmMTExNGVkOWIxNzRhMzM1YTcyMjk5YTgwZmE3ZDFhMjgyMmEzNiIsCiAgICAidGFyZ2V0UmVsZWFzZVNoYTI1NiI6ICI2ZjJhZDQ3Njg4YmQxY2VlMTljMzkyOTQ4OWYzODQwMDk1ZGVkOGYzNzNmYTBjZjJhN2E4YTNiMjg2Y2NiMGNmIgogIH0sCiAgImRvY3VtZW50VHlwZSI6ICJzdG9yZS1yZWNlaXB0IiwKICAib3BlcmF0aW9uSW50ZW50U2hhMjU2IjogIjI0Yjk4MjljN2VlNThmNTc5ZWM4MmYxNmNjNDY5ZDViMjc2NDEwNTRiYWVjZTU4MWJlYzU4OGNiMzcwZjhiMjkiLAogICJhdXRob3JpemVkQnkiOiB7CiAgICAid29ya2Zsb3ciOiAiTW9iaWxlIGNhbmRpZGF0ZSIsCiAgICAiY2FsbGVyUGF0aCI6ICIuZ2l0aHViL3dvcmtmbG93cy9tb2JpbGUtY2FuZGlkYXRlLnltbCIsCiAgICAicmV1c2FibGVSZXBvc2l0b3J5IjogImV4YW1wbGUvbW9iaWxlLXJlbGVhc2Uta2l0IiwKICAgICJyZXVzYWJsZVBhdGgiOiAiLmdpdGh1Yi93b3JrZmxvd3MvcmV1c2FibGUtY2FuZGlkYXRlLnltbCIsCiAgICAicmV1c2FibGVDb21taXQiOiAiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIsCiAgICAicnVuSWQiOiAiMTAwMDAwMDAwMCIsCiAgICAiYXR0ZW1wdCI6IDEsCiAgICAiaGVhZFNoYSI6ICIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyIiwKICAgICJyZWYiOiAicmVmcy9oZWFkcy9tYWluIiwKICAgICJldmVudCI6ICJ3b3JrZmxvd19kaXNwYXRjaCIKICB9LAogICJleGVjdXRlZEJ5IjogewogICAgIndvcmtmbG93IjogIk1vYmlsZSBjYW5kaWRhdGUiLAogICAgImNhbGxlclBhdGgiOiAiLmdpdGh1Yi93b3JrZmxvd3MvbW9iaWxlLWNhbmRpZGF0ZS55bWwiLAogICAgInJldXNhYmxlUmVwb3NpdG9yeSI6ICJleGFtcGxlL21vYmlsZS1yZWxlYXNlLWtpdCIsCiAgICAicmV1c2FibGVQYXRoIjogIi5naXRodWIvd29ya2Zsb3dzL3JldXNhYmxlLWNhbmRpZGF0ZS55bWwiLAogICAgInJldXNhYmxlQ29tbWl0IjogIjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLAogICAgInJ1bklkIjogIjEwMDAwMDAwMDAiLAogICAgImF0dGVtcHQiOiAxLAogICAgImhlYWRTaGEiOiAiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsCiAgICAicmVmIjogInJlZnMvaGVhZHMvbWFpbiIsCiAgICAiZXZlbnQiOiAid29ya2Zsb3dfZGlzcGF0Y2giCiAgfSwKICAicHJvZHVjZWRCeSI6IHsKICAgICJ3b3JrZmxvdyI6ICJNb2JpbGUgY2FuZGlkYXRlIiwKICAgICJjYWxsZXJQYXRoIjogIi5naXRodWIvd29ya2Zsb3dzL21vYmlsZS1jYW5kaWRhdGUueW1sIiwKICAgICJyZXVzYWJsZVJlcG9zaXRvcnkiOiAiZXhhbXBsZS9tb2JpbGUtcmVsZWFzZS1raXQiLAogICAgInJldXNhYmxlUGF0aCI6ICIuZ2l0aHViL3dvcmtmbG93cy9yZXVzYWJsZS1jYW5kaWRhdGUueW1sIiwKICAgICJyZXVzYWJsZUNvbW1pdCI6ICIxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwKICAgICJydW5JZCI6ICIxMDAwMDAwMDAwIiwKICAgICJhdHRlbXB0IjogMSwKICAgICJoZWFkU2hhIjogIjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLAogICAgInJlZiI6ICJyZWZzL2hlYWRzL21haW4iLAogICAgImV2ZW50IjogIndvcmtmbG93X2Rpc3BhdGNoIgogIH0sCiAgImludGVncml0eSI6IHsKICAgICJhbGdvcml0aG0iOiAic2hhMjU2IiwKICAgICJzaGEyNTYiOiAiMjYzM2MyYTQ0OTY3YjZjYzY5MDBmM2Y4ODgzMWQzODNiMGI1YjFmNDNkMDg3NmQ2ZjhiN2I0ZmNkZGE1MzAxOCIKICB9Cn0K", 3363, "375d5b895b62b62842338acff9c8ed9cfafe9a618eb51439d9ebc042d401e183"),
            ("evidence/operation/candidate-operation-intent.json", "ewogICJkb2N1bWVudFR5cGUiOiAic3RvcmUtb3BlcmF0aW9uLWludGVudCIsCiAgInNjaGVtYVZlcnNpb24iOiAxLAogICJzdGFnZSI6ICJjYW5kaWRhdGUiLAogICJwbGF0Zm9ybSI6ICJhbmRyb2lkIiwKICAidG9vbGluZyI6IHsKICAgICJ2ZXJzaW9uIjogIjAuMi4wIiwKICAgICJjb21taXQiOiAiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIKICB9LAogICJyZXBvc2l0b3J5IjogewogICAgImZ1bGxOYW1lIjogImV4YW1wbGUvbW9iaWxlLWFwcCIsCiAgICAiaWQiOiAiMTAwMDAwMDAwIgogIH0sCiAgImNhbmRpZGF0ZVNvdXJjZSI6IHsKICAgICJjb21taXQiOiAiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsCiAgICAidHJlZSI6ICIzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzIiwKICAgICJyZWYiOiAicmVmcy9oZWFkcy9tYWluIgogIH0sCiAgIm9wZXJhdGlvblNvdXJjZSI6IHsKICAgICJjb21taXQiOiAiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsCiAgICAidHJlZSI6ICIzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzIiwKICAgICJyZWYiOiAicmVmcy9oZWFkcy9tYWluIgogIH0sCiAgImF1dGhvcml6ZWRCeSI6IHsKICAgICJ3b3JrZmxvdyI6ICJNb2JpbGUgY2FuZGlkYXRlIiwKICAgICJjYWxsZXJQYXRoIjogIi5naXRodWIvd29ya2Zsb3dzL21vYmlsZS1jYW5kaWRhdGUueW1sIiwKICAgICJyZXVzYWJsZVJlcG9zaXRvcnkiOiAiZXhhbXBsZS9tb2JpbGUtcmVsZWFzZS1raXQiLAogICAgInJldXNhYmxlUGF0aCI6ICIuZ2l0aHViL3dvcmtmbG93cy9yZXVzYWJsZS1jYW5kaWRhdGUueW1sIiwKICAgICJyZXVzYWJsZUNvbW1pdCI6ICIxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwKICAgICJydW5JZCI6ICIxMDAwMDAwMDAwIiwKICAgICJhdHRlbXB0IjogMSwKICAgICJoZWFkU2hhIjogIjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLAogICAgInJlZiI6ICJyZWZzL2hlYWRzL21haW4iLAogICAgImV2ZW50IjogIndvcmtmbG93X2Rpc3BhdGNoIgogIH0sCiAgImNvbmZpcm1hdGlvbiI6ICJjYW5kaWRhdGU6YW5kcm9pZDoxLjIuMzo0MiIsCiAgImFwcGxpY2F0aW9uIjogewogICAgImlkIjogImNvbS5leGFtcGxlLnJlYWRlciIKICB9LAogICJ2ZXJzaW9uIjogewogICAgIm1hcmtldGluZyI6ICIxLjIuMyIsCiAgICAiYnVpbGQiOiA0MgogIH0sCiAgImRlc3RpbmF0aW9uIjogewogICAgImNoYW5uZWwiOiAiaW50ZXJuYWwiLAogICAgInJlbGVhc2VTdGF0dXMiOiAiY29tcGxldGVkIgogIH0sCiAgImNvbmZpZ3VyYXRpb24iOiB7CiAgICAicGF0aCI6ICJyZWxlYXNlL21vYmlsZS1yZWxlYXNlLmpzb24iLAogICAgInNoYTI1NiI6ICI0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0IiwKICAgICJtZXRhZGF0YVNoYTI1NiI6ICI1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1IgogIH0sCiAgImFydGlmYWN0cyI6IFsKICAgIHsKICAgICAgImxvZ2ljYWxOYW1lIjogImFuZHJvaWQtYWFiIiwKICAgICAgInBsYXRmb3JtIjogImFuZHJvaWQiLAogICAgICAia2luZCI6ICJhYWIiLAogICAgICAiZmlsZU5hbWUiOiAicmVhZGVyLTEuMi4zLTQyLmFhYiIsCiAgICAgICJzaXplIjogMTIzNDU2NzgsCiAgICAgICJzaGEyNTYiOiAiNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NiIsCiAgICAgICJhcmNoaXRlY3R1cmVzIjogWwogICAgICAgICJhcm02NC12OGEiLAogICAgICAgICJ4ODZfNjQiCiAgICAgIF0KICAgIH0sCiAgICB7CiAgICAgICJsb2dpY2FsTmFtZSI6ICJzdG9yZS1tZXRhZGF0YSIsCiAgICAgICJwbGF0Zm9ybSI6ICJzaGFyZWQiLAogICAgICAia2luZCI6ICJtZXRhZGF0YSIsCiAgICAgICJmaWxlTmFtZSI6ICJzdG9yZS1tZXRhZGF0YS0xLjIuMy00Mi56aXAiLAogICAgICAic2l6ZSI6IDM0NTY3LAogICAgICAic2hhMjU2IjogIjU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTUiLAogICAgICAiYXJjaGl0ZWN0dXJlcyI6IFtdCiAgICB9LAogICAgewogICAgICAibG9naWNhbE5hbWUiOiAidmFsaWRhdGlvbi1yZXBvcnQiLAogICAgICAicGxhdGZvcm0iOiAic2hhcmVkIiwKICAgICAgImtpbmQiOiAidmFsaWRhdGlvbi1yZXBvcnQiLAogICAgICAiZmlsZU5hbWUiOiAidmFsaWRhdGlvbi1yZXBvcnQtMS4yLjMtNDIuanNvbiIsCiAgICAgICJzaXplIjogMjM0NSwKICAgICAgInNoYTI1NiI6ICI3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3IiwKICAgICAgImFyY2hpdGVjdHVyZXMiOiBbXQogICAgfQogIF0sCiAgInNpZ25pbmciOiBbCiAgICB7CiAgICAgICJwbGF0Zm9ybSI6ICJhbmRyb2lkIiwKICAgICAgImtpbmQiOiAiYW5kcm9pZC11cGxvYWQiLAogICAgICAiY2VydGlmaWNhdGVTaGEyNTYiOiAiYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYSIKICAgIH0KICBdLAogICJwcmVkZWNlc3NvcnMiOiB7fSwKICAic3RvcmVQcmVjb25kaXRpb24iOiB7CiAgICAic2NoZW1hVmVyc2lvbiI6IDEsCiAgICAiZG9jdW1lbnRUeXBlIjogInN0b3JlLXByZWNvbmRpdGlvbiIsCiAgICAib3BlcmF0aW9uIjogImFuZHJvaWRfaW50ZXJuYWxfdXBsb2FkIiwKICAgICJwbGF0Zm9ybSI6ICJhbmRyb2lkIiwKICAgICJhcHBJZGVudGl0eSI6ICJjb20uZXhhbXBsZS5yZWFkZXIiLAogICAgIm1hcmtldGluZ1ZlcnNpb24iOiAiMS4yLjMiLAogICAgImJ1aWxkTnVtYmVyIjogNDIsCiAgICAib2JzZXJ2ZWRBdCI6ICIyMDI2LTAxLTAxVDAwOjAwOjAwWiIsCiAgICAic25hcHNob3QiOiB7CiAgICAgICJjYW5vbmljYWxpemF0aW9uIjogIm1yay1wbGF5LW9wZXJhdGlvbi12MSIsCiAgICAgICJkZXN0aW5hdGlvblRyYWNrIjogImludGVybmFsIiwKICAgICAgImRlc3RpbmF0aW9uU3RhdGUiOiB7CiAgICAgICAgImNhbm9uaWNhbGl6YXRpb24iOiAibXJrLXBsYXktdHJhY2stc3RhdGUtdjIiLAogICAgICAgICJ0cmFjayI6ICJpbnRlcm5hbCIsCiAgICAgICAgInJlbGVhc2VzIjogW10KICAgICAgfSwKICAgICAgInNvdXJjZVRyYWNrIjogbnVsbCwKICAgICAgInNvdXJjZVN0YXRlIjogbnVsbCwKICAgICAgImJ1bmRsZXMiOiBbXSwKICAgICAgInRhcmdldFByZXNlbnQiOiBmYWxzZSwKICAgICAgInRhcmdldFJlbGVhc2UiOiB7CiAgICAgICAgIm5hbWUiOiAiMS4yLjMiLAogICAgICAgICJzdGF0dXMiOiAiY29tcGxldGVkIiwKICAgICAgICAidmVyc2lvbkNvZGVzIjogWwogICAgICAgICAgIjQyIgogICAgICAgIF0KICAgICAgfSwKICAgICAgImRlc3RpbmF0aW9uVGFyZ2V0U3RhdGUiOiB7CiAgICAgICAgImNhbm9uaWNhbGl6YXRpb24iOiAibXJrLXBsYXktdHJhY2stc3RhdGUtdjIiLAogICAgICAgICJ0cmFjayI6ICJpbnRlcm5hbCIsCiAgICAgICAgInJlbGVhc2VzIjogWwogICAgICAgICAgewogICAgICAgICAgICAibmFtZSI6ICIxLjIuMyIsCiAgICAgICAgICAgICJzdGF0dXMiOiAiY29tcGxldGVkIiwKICAgICAgICAgICAgInZlcnNpb25Db2RlcyI6IFsKICAgICAgICAgICAgICAiNDIiCiAgICAgICAgICAgIF0KICAgICAgICAgIH0KICAgICAgICBdCiAgICAgIH0sCiAgICAgICJzb3VyY2VBbGxvd2VkU3RhdGVzIjogW10KICAgIH0KICB9LAogICJwcml2YXRlU3RhdGVDb21taXRtZW50cyI6IHt9LAogICJjcmVhdGVkQXQiOiAiMjAyNi0wMS0wMVQwMDowMDowMFoiLAogICJpbnRlZ3JpdHkiOiB7CiAgICAiYWxnb3JpdGhtIjogInNoYTI1NiIsCiAgICAic2hhMjU2IjogIjI0Yjk4MjljN2VlNThmNTc5ZWM4MmYxNmNjNDY5ZDViMjc2NDEwNTRiYWVjZTU4MWJlYzU4OGNiMzcwZjhiMjkiCiAgfQp9Cg==", 4096, "e56ad77ee3cb4b1d3e12d1a6f5be8f7d0e90497934d1ebbd5bd9312b53362e42")
        ]
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
        private var androidPositiveProfile = false
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
        var evidencePath: String { rootPath + "/evidence" }
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
        // Only the two successful mkdtemp call sites below may initialize a
        // new empty 0700 root. Never change a parent, adopted handoff or user input.
        private static func initializeNewPrivateRootGroup(_ fd: Int32, parent: Int32, name: String,
                                                          created: StatFacts) throws -> StatFacts {
            try need(fd >= 0 && created.mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
                && created.uid == getuid() && created.mode & 0o7777 == 0o700 && created.flags == 0
                && created == facts(fd) && created == named(parent, name),
                "new private root initialization precondition")
            let group = getgid()
            let changed = created.gid != group
            if changed {
                // The UID sentinel leaves the owner unchanged; no pathname mutation.
                try need(Darwin.fchown(fd, uid_t.max, group) == 0, "new private root group initialization failed")
            }
            let after = try facts(fd)
            let transition: Bool
            if changed {
                // Only this requested GID and its ctime may differ. Do not discard
                // other metadata changes or require clock-resolution advancement.
                transition = created.device == after.device && created.inode == after.inode
                    && created.mode == after.mode && created.uid == after.uid && created.flags == after.flags
                    && created.links == after.links && created.bytes == after.bytes
                    && created.modifiedSeconds == after.modifiedSeconds
                    && created.modifiedNanoseconds == after.modifiedNanoseconds
            } else {
                transition = created == after // A no-op keeps the complete original, including ctime.
            }
            try need(transition && after.gid == group && after == facts(fd) && after == named(parent, name),
                     "new private root initialization transition differs")
            return after // Callers rebaseline only after this complete original POST.
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
        private func readLeaf(_ original: Directory, name: String, privateOnly: Bool = false, limit: Int = 32 * 1024) throws -> File {
            try Self.need(closeErrors.isEmpty, "an earlier consuming close failed")
            try checkDirectory(original)
            let fd = openat(original.fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            try Self.need(fd >= 0, "fixed leaf open failed")
            defer { if Darwin.close(fd) != 0 { closeErrors.append("fixed-leaf-close") } }
            let before = try Self.facts(fd)
            try Self.need(before.mode & mode_t(S_IFMT) == mode_t(S_IFREG) && before.links == 1
                && before.uid == getuid() && before.gid == getgid() && before.bytes >= 0 && before.bytes <= limit
                && before.mode & 0o7022 == 0
                && (!privateOnly || before.mode & 0o7777 == 0o600 && before.flags == 0
                    && before.device == original.facts.device), "leaf shape/mode/limit")
            var bytes = Data(), buffer = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
                try Self.need(count >= 0, "fixed leaf read failed")
                if count == 0 { break }
                try Self.need(bytes.count + count <= limit, "fixed leaf read limit")
                bytes.append(contentsOf: buffer.prefix(count))
            }
            try Self.need(bytes.count == before.bytes && before == Self.facts(fd)
                && before == Self.named(original.fd, name), "fixed leaf changed during observation")
            return File(bytes: bytes, facts: before)
        }
        private static let androidPositivePaths: Set<String> = [
            "project/.github/workflows/keep-user.yml",
            "project/.gitignore",
            "project/README-user.txt",
            "project/app/build.gradle",
            "project/app/gradle.lockfile",
            "project/app/src/main/AndroidManifest.xml",
            "project/app/src/main/java/org/example/saved/MainActivity.java",
            "project/build.gradle",
            "project/buildscript-gradle.lockfile",
            "project/gradle/wrapper/gradle-wrapper.properties",
            "project/release/mobile-release.json",
            "project/release/store/android/en-US/full_description.txt",
            "project/release/store/android/en-US/short_description.txt",
            "project/release/store/android/en-US/title.txt",
            "project/release/version.properties",
            "project/settings.gradle",
        ]
        private static let androidPositiveBytes = 15_695
        private static let androidPositiveSHA256 = "f0936a01330d095da8863571d78c1580e037d6d2a69d26c19a31814ffa251f4e"

        // One runtime-PUBLIC certificate substitution, before ordinary Save.
        // No private key/identity-status/Store authority enters this DATA stage.
        func prepareAndroidCertificate(_ certificate: String) throws {
            try Self.need(androidPositiveProfile && changes.isEmpty && acceptedStages.isEmpty && androidOutput == nil
                && certificate.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
                && certificate != String(repeating: "0", count: 64), "Android public certificate stage admission")
            let template = "{\n  \"schemaVersion\": 1,\n  \"version\": {\n    \"source\": \"release/version.properties\",\n    \"nameKey\": \"VERSION_NAME\",\n    \"buildKey\": \"BUILD_NUMBER\"\n  },\n  \"source\": {\n    \"candidateBranch\": \"main\",\n    \"productionBranch\": \"main\"\n  },\n  \"android\": {\n    \"enabled\": true,\n    \"module\": \":app\",\n    \"variant\": \"release\",\n    \"applicationId\": \"org.example.saved\",\n    \"identityStatus\": \"unverified\",\n    \"uploadCertificateSha256\": \"MRK_PUBLIC_CERTIFICATE_64HEX\"\n  },\n  \"ios\": {\n    \"enabled\": false\n  },\n  \"metadata\": {\n    \"root\": \"release/store\",\n    \"androidLocales\": [\n      \"en-US\"\n    ],\n    \"iosLocales\": []\n  },\n  \"services\": {\n    \"androidFirebase\": \"disabled\",\n    \"iosFirebase\": \"disabled\"\n  },\n  \"projectChecks\": {\n    \"preflight\": [],\n    \"androidArtifact\": [],\n    \"iosArtifact\": []\n  }\n}\n"
            let config = Data(template.replacingOccurrences(of: "MRK_PUBLIC_CERTIFICATE_64HEX", with: certificate).utf8)
            let ignore = Data("/.mobile-release/\n/.gradle/\n/build/\n/app/build/\n.mobile-release-init-prepare/\n.mobile-release-init/\n.mobile-release-init-cleanup/\n.mobile-release-metadata-text-prepare/\n.mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n.mobile-release-version-prepare/\n.mobile-release-version/\n.mobile-release-version-cleanup/\n.mobile-release-metadata-images-prepare/\n.mobile-release-metadata-images/\n.mobile-release-metadata-images-cleanup/\n".utf8)
            try Self.need(config.count <= 32 * 1024 && ignore.count <= 32 * 1024
                && originals[Self.config] != nil && originals["project/.gitignore"] != nil,
                "Android exact public stage bound")
            changes["android-public-certificate"] = [Self.config: config, "project/.gitignore": ignore]
            try assertUnchanged()
        }

        // Exactly one same-job PRIVATE role. These are comparison originals,
        // not product leases, legal acknowledgment, or authority to delete.
        final class AndroidInputs {
            private struct Leaf { let fd: Int32; let parent: Int32; let name: String; let original: File }
            private var descriptors: [Int32] = []
            private var held: [(Directory, Bool)] = []
            private var leaves: [String: Leaf] = [:]
            private var credentialDirectory: Directory?
            private var scalars: [String: String] = [:]
            private(set) var rootPath = ""
            private(set) var publicCertificate = ""
            private(set) var closed = false
            private(set) var terminalClose = false
            private static let roles = ["jdk": "tools/jdk/temurin-17.jdk", "sdk": "tools/sdk", "gradle": "tools/gradle"]
            private static let fileNames: Set<String> = ["upload.jks", "upload.der", "scalars.json"]
            private static let catalogue = "1d1c1f0f49836180853285d49e114b12c44c9d72c41250b103c5dd34fa792203"

            private static func matches(_ value: String, _ pattern: String) -> Bool {
                value.range(of: pattern, options: .regularExpression) != nil
            }
            private static func exactObject(_ value: Any?, keys: Set<String>) throws -> [String: Any] {
                guard let object = value as? [String: Any], Set(object.keys) == keys else {
                    throw Refusal.condition("Android private object shape differs")
                }
                return object
            }
            private static func wire(_ value: Any?) throws -> [String] {
                guard let values = value as? [String], values.count == 10,
                      values.allSatisfy({ matches($0, #"^(0|[1-9][0-9]{0,19})$"#) }) else {
                    throw Refusal.condition("Android private fact shape differs")
                }
                return values
            }
            private static func digest(_ value: Any?) throws -> String {
                guard let text = value as? String, matches(text, #"^[0-9a-f]{64}$"#) else {
                    throw Refusal.condition("Android private digest shape differs")
                }
                return text
            }
            private static func canonical(_ object: [String: Any]) throws -> Data {
                try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) + Data([10])
            }
            private func directory(_ parent: Directory?, name: String, full: Bool = false,
                                   mode: mode_t? = nil, check: () throws -> Void) throws -> Directory {
                try check()
                let fd = parent.map { openat($0.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
                    ?? open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                try LocalFixture.need(fd >= 0, "Android private directory open")
                descriptors.append(fd)
                let before = try LocalFixture.facts(fd)
                try LocalFixture.need(before.mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
                    && (before.uid == 0 || before.uid == getuid()) && before.mode & 0o022 == 0 && before.flags == 0,
                    "Android private directory shape")
                if let parent {
                    try LocalFixture.need(before == LocalFixture.androidOutputNamed(parent.fd, name),
                                          "Android private directory binding")
                }
                if let mode {
                    try LocalFixture.need(before.mode & 0o7777 == mode && before.uid == getuid()
                        && before.gid == getgid(), "Android private owned directory")
                }
                let value = Directory(fd: fd, parent: parent?.fd, name: name, facts: before)
                held.append((value, full))
                try LocalFixture.need(held.count <= 14, "Android private directory bound")
                return value
            }
            private func directoryPost(_ value: Directory, full: Bool) throws {
                let actual = try LocalFixture.facts(value.fd)
                try LocalFixture.need(full ? actual == value.facts : actual.sameDirectory(value.facts),
                                      "Android private original directory changed")
                if let parent = value.parent {
                    let named = try LocalFixture.androidOutputNamed(parent, value.name)
                    try LocalFixture.need(full ? actual == named : actual.sameDirectory(named),
                                          "Android private named ancestor changed")
                }
            }
            private func body(_ fd: Int32, parent: Directory, name: String, limit: Int,
                              check: () throws -> Void) throws -> File {
                try check()
                let before = try LocalFixture.facts(fd)
                try LocalFixture.need(before.mode & mode_t(S_IFMT) == mode_t(S_IFREG)
                    && before.mode & 0o7777 == 0o600 && before.links == 1 && before.uid == getuid()
                    && before.gid == getgid() && before.flags == 0 && before.device == parent.facts.device
                    && before.bytes > 0 && before.bytes <= limit,
                    "Android private original file shape")
                var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
                while true {
                    try check()
                    let count = buffer.withUnsafeMutableBytes { Darwin.pread(fd, $0.baseAddress!, $0.count, off_t(data.count)) }
                    try LocalFixture.need(count >= 0 && data.count + count <= limit, "Android private bounded read")
                    if count == 0 { break }
                    data.append(contentsOf: buffer.prefix(count))
                }
                try LocalFixture.need(data.count == before.bytes && before == LocalFixture.facts(fd)
                    && before == LocalFixture.androidOutputNamed(parent.fd, name), "Android private file POST")
                try check()
                return File(bytes: data, facts: before)
            }
            private func leaf(_ parent: Directory, name: String, limit: Int,
                              check: () throws -> Void) throws -> File {
                try LocalFixture.need(leaves[name] == nil, "Android private repeated leaf")
                let fd = openat(parent.fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                try LocalFixture.need(fd >= 0, "Android private fixed leaf open")
                descriptors.append(fd)
                let original = try body(fd, parent: parent, name: name, limit: limit, check: check)
                leaves[name] = Leaf(fd: fd, parent: parent.fd, name: name, original: original)
                return original
            }
            private func credentialNames(check: () throws -> Void) throws {
                guard let directory = credentialDirectory else { throw Refusal.condition("Android private credential directory absent") }
                try directoryPost(directory, full: true); try check()
                let fd = openat(directory.fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                try LocalFixture.need(fd >= 0, "Android private enumeration open")
                guard let stream = fdopendir(fd) else {
                    _ = Darwin.close(fd)
                    throw Refusal.condition("Android private enumeration conversion")
                }
                var primary: Error?, names: Set<String> = []
                do {
                    while true {
                        try check(); errno = 0
                        guard let value = readdir(stream) else {
                            try LocalFixture.need(errno == 0, "Android private enumeration read"); break
                        }
                        let name = withUnsafePointer(to: &value.pointee.d_name) {
                            $0.withMemoryRebound(to: CChar.self, capacity: Int(NAME_MAX) + 1) { String(cString: $0) }
                        }
                        if name == "." || name == ".." { continue }
                        try LocalFixture.need(names.count < 3 && Self.fileNames.contains(name) && names.insert(name).inserted,
                                              "Android private credential roster")
                    }
                    try LocalFixture.need(names == Self.fileNames, "Android private credential roster incomplete")
                    try directoryPost(directory, full: true)
                } catch { primary = error }
                if closedir(stream) != 0 && primary == nil { primary = Refusal.condition("Android private enumeration close") }
                do { try check() } catch { if primary == nil { primary = error } }
                if let primary { throw primary }
            }
            private func load(normal: Directory, path: String, source: String, run: String, attempt: String,
                              check: () throws -> Void) throws {
                rootPath = path + "/android-inputs"
                let handoff = try leaf(normal, name: "android-input-fixture.json", limit: 16 * 1024, check: check)
                var object = try Self.exactObject(JSONSerialization.jsonObject(with: handoff.bytes), keys: [
                    "schemaVersion", "scope", "sourceCommit", "target", "runId", "runAttempt", "workflow", "ref", "root",
                    "rootFacts", "credentialDirectoryFacts", "sourceCatalogueSha256", "sourceRosterSha256", "roots", "files",
                    "publicCertificateSha256", "keyCommands", "parentReturncodeRequired", "phaseClock"])
                try LocalFixture.need(object["schemaVersion"] as? Int == 1 && object["parentReturncodeRequired"] as? Int == 0
                    && object["scope"] as? String == "one-owned-android-ui-inputs" && object["sourceCommit"] as? String == source
                    && object["target"] as? String == "aarch64-apple-darwin" && object["runId"] as? String == run
                    && object["runAttempt"] as? String == attempt && object["root"] as? String == rootPath
                    && object["workflow"] as? String == ".github/workflows/desktop-macos-installed.yml"
                    && object["ref"] as? String == "refs/heads/verify/desktop-macos-installed"
                    && object["sourceCatalogueSha256"] as? String == Self.catalogue,
                    "Android private current context differs")
                object["schemaVersion"] = 1; object["parentReturncodeRequired"] = 0
                _ = try Self.digest(object["sourceRosterSha256"])
                publicCertificate = try Self.digest(object["publicCertificateSha256"])
                var phase = try Self.exactObject(object["phaseClock"], keys: ["startNs", "deadlineNs", "beforePublicationNs", "postCloseDeadlineRequired"])
                guard let startText = phase["startNs"] as? String, let deadlineText = phase["deadlineNs"] as? String,
                      let beforeText = phase["beforePublicationNs"] as? String,
                      [startText, deadlineText, beforeText].allSatisfy({ Self.matches($0, #"^[1-9][0-9]{0,19}$"#) }),
                      let start = UInt64(startText), let deadline = UInt64(deadlineText), let before = UInt64(beforeText),
                      deadline > start, deadline - start == 1_200_000_000_000, start <= before, before < deadline,
                      phase["postCloseDeadlineRequired"] as? Bool == true else {
                    throw Refusal.condition("Android private original phase clock differs")
                }
                phase["postCloseDeadlineRequired"] = true; object["phaseClock"] = phase
                guard let commands = object["keyCommands"] as? [[String: Any]], commands.count == 2 else {
                    throw Refusal.condition("Android private command roster differs")
                }
                var normalized: [[String: Any]] = []
                for (index, value) in commands.enumerated() {
                    var row = try Self.exactObject(value, keys: ["role", "returncode", "timeoutSeconds", "roleCapSeconds",
                        "outputLimitBytes", "argvSha256", "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256"])
                    guard row["role"] as? String == ["android-ui-disposable-jks", "android-ui-public-certificate"][index],
                          row["returncode"] as? Int == 0, row["roleCapSeconds"] as? Int == 30,
                          row["outputLimitBytes"] as? Int == 2_097_152,
                          let timeout = row["timeoutSeconds"] as? Int, (1...30).contains(timeout),
                          let out = row["stdoutBytes"] as? Int, let err = row["stderrBytes"] as? Int,
                          out >= 0, out <= 2_097_152, err >= 0, err <= 2_097_152 - out else {
                        throw Refusal.condition("Android private original command differs")
                    }
                    for key in ["argvSha256", "stdoutSha256", "stderrSha256"] { _ = try Self.digest(row[key]) }
                    row["returncode"] = 0; row["roleCapSeconds"] = 30; row["outputLimitBytes"] = 2_097_152
                    row["timeoutSeconds"] = timeout; row["stdoutBytes"] = out; row["stderrBytes"] = err
                    normalized.append(row)
                }
                object["keyCommands"] = normalized
                let roots = try Self.exactObject(object["roots"], keys: Set(Self.roles.keys))
                let files = try Self.exactObject(object["files"], keys: Self.fileNames)
                for (role, relative) in Self.roles {
                    let row = try Self.exactObject(roots[role], keys: ["relative", "facts"])
                    try LocalFixture.need(row["relative"] as? String == relative, "Android private fixed source path")
                    _ = try Self.wire(row["facts"])
                }
                for name in Self.fileNames {
                    let row = try Self.exactObject(files[name], keys: ["relative", "facts", "sha256"])
                    try LocalFixture.need(row["relative"] as? String == "credentials/" + name, "Android private fixed credential path")
                    _ = try Self.wire(row["facts"]); _ = try Self.digest(row["sha256"])
                }
                // Reconstruct numeric/boolean fields before byte equality, so
                // JSON booleans/coerced numbers and duplicate keys cannot pass.
                try LocalFixture.need(try Self.canonical(object) == handoff.bytes, "Android private canonical document differs")
                let root = try directory(normal, name: "android-inputs", full: true, mode: 0o700, check: check)
                let credentials = try directory(root, name: "credentials", full: true, mode: 0o700, check: check)
                credentialDirectory = credentials
                try LocalFixture.need(try LocalFixture.wireFacts(root.facts) == Self.wire(object["rootFacts"])
                    && LocalFixture.wireFacts(credentials.facts) == Self.wire(object["credentialDirectoryFacts"]),
                    "Android private held root facts differ")
                let tools = try directory(root, name: "tools", full: true, mode: 0o700, check: check)
                let jdk = try directory(tools, name: "jdk", full: true, mode: 0o755, check: check)
                let observed = ["jdk": try directory(jdk, name: "temurin-17.jdk", full: true, mode: 0o755, check: check),
                    "sdk": try directory(tools, name: "sdk", full: true, mode: 0o755, check: check),
                    "gradle": try directory(tools, name: "gradle", full: true, mode: 0o755, check: check)]
                for (role, directory) in observed {
                    let row = roots[role] as! [String: Any]
                    try LocalFixture.need(try LocalFixture.wireFacts(directory.facts) == Self.wire(row["facts"])
                        && directory.facts.device == root.facts.device, "Android private source root differs")
                }
                var total = handoff.bytes.count
                for name in Self.fileNames.sorted() {
                    let file = try leaf(credentials, name: name, limit: 32 * 1024, check: check)
                    let row = files[name] as! [String: Any]
                    let hash = SHA256.hash(data: file.bytes).map { String(format: "%02x", $0) }.joined()
                    try LocalFixture.need(try LocalFixture.wireFacts(file.facts) == Self.wire(row["facts"])
                        && hash == Self.digest(row["sha256"]), "Android private current leaf differs")
                    if name == "upload.der" { try LocalFixture.need(hash == publicCertificate, "Android public certificate differs") }
                    if name == "scalars.json" {
                        let parsed = try Self.exactObject(JSONSerialization.jsonObject(with: file.bytes), keys: ["alias", "storePassword", "keyPassword"])
                        guard let alias = parsed["alias"] as? String, alias == "mrk-disposable-android-ui",
                              let store = parsed["storePassword"] as? String, let key = parsed["keyPassword"] as? String,
                              Self.matches(store, #"^[0-9a-f]{48}$"#), Self.matches(key, #"^[0-9a-f]{48}$"#),
                              try Self.canonical(parsed) == file.bytes else {
                            throw Refusal.condition("Android private scalar shape differs")
                        }
                        scalars = ["alias": alias, "storePassword": store, "keyPassword": key]
                    }
                    total += file.bytes.count
                }
                try LocalFixture.need(total <= 256 * 1024 && descriptors.count == 18 && held.count == 14 && leaves.count == 4,
                                      "Android private complete original census differs")
                try post(check: check)
            }
            static func admit(check: () throws -> Void) throws -> AndroidInputs {
                let env = ProcessInfo.processInfo.environment
                guard let source = env["MRK_NORMAL_UI_HARNESS_SOURCE"], Self.matches(source, #"^[0-9a-f]{40}$"#),
                      env["MRK_NORMAL_UI_APPLICATION_SOURCE"] == source,
                      env["MRK_NORMAL_UI_HOSTED_JOB"] == "github-hosted-macos26-arm64",
                      let run = env["MRK_NORMAL_UI_ANDROID_RUN_ID"], Self.matches(run, #"^[1-9][0-9]{0,19}$"#),
                      let attempt = env["MRK_NORMAL_UI_ANDROID_RUN_ATTEMPT"], Self.matches(attempt, #"^[1-9][0-9]{0,19}$"#),
                      let handoff = env["MRK_NORMAL_UI_ANDROID_INPUT_FIXTURE"],
                      Self.matches(handoff, #"^/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}/normal-ui/android-input-fixture\.json$"#) else {
                    throw Refusal.condition("Android private fixed current context absent")
                }
                let normal = String(handoff.dropLast("/android-input-fixture.json".count))
                let value = AndroidInputs()
                do {
                    var parent = try value.directory(nil, name: "/", check: check)
                    for name in normal.split(separator: "/").map(String.init) {
                        let mode: mode_t? = name == "normal-ui" || name.hasPrefix("mrk-macos-installed.") ? 0o700 : nil
                        parent = try value.directory(parent, name: name, mode: mode, check: check)
                    }
                    try value.load(normal: parent, path: normal, source: source, run: run, attempt: attempt, check: check)
                    return value
                } catch {
                    let primary = error
                    do { try value.close(check: check) } catch { /* Primary failure remains authoritative. */ }
                    throw primary
                }
            }
            func post(check: () throws -> Void) throws {
                try LocalFixture.need(!closed, "Android private original already consumed")
                try check()
                for (directory, full) in held { try directoryPost(directory, full: full); try check() }
                try credentialNames(check: check)
                for leaf in leaves.values {
                    guard let parent = held.first(where: { $0.0.fd == leaf.parent })?.0 else {
                        throw Refusal.condition("Android private original parent absent")
                    }
                    let current = try body(leaf.fd, parent: parent, name: leaf.name,
                                           limit: leaf.name == "android-input-fixture.json" ? 16 * 1024 : 32 * 1024, check: check)
                    try LocalFixture.need(current.bytes == leaf.original.bytes && current.facts == leaf.original.facts,
                                          "Android private original changed")
                }
                try check()
            }
            func sourcePath(_ role: String) throws -> String {
                guard !closed, let relative = Self.roles[role] else { throw Refusal.condition("Android fixed source role unavailable") }
                return rootPath + "/" + relative
            }
            func credentialPath() throws -> String {
                try LocalFixture.need(!closed && leaves["upload.jks"] != nil, "Android private key unavailable")
                return rootPath + "/credentials"
            }
            func scalar(_ name: String) throws -> String {
                guard !closed, let value = scalars[name] else { throw Refusal.condition("Android private scalar unavailable") }
                return value
            }
            func close(check: () throws -> Void) throws {
                if closed { return }
                var primary: Error?
                while let fd = descriptors.popLast() {
                    if Darwin.close(fd) != 0 && primary == nil { primary = Refusal.condition("Android private original close failed") }
                }
                held.removeAll(); leaves.removeAll(); scalars.removeAll(); credentialDirectory = nil; closed = true
                do { try check() } catch { if primary == nil { primary = error } }
                if let primary { throw primary }
            }
            func finish(check: () throws -> Void) throws {
                var primary: Error?
                do { try post(check: check) } catch { primary = error }
                do { try close(check: check) } catch { if primary == nil { primary = error } }
                if let primary { throw primary }
                terminalClose = true
            }
        }

        // Fixed public XML prerequisite only. No current Profile calls these
        // helpers, no generic JSON/leaf limit changes, and no Android UI claim.
        // A future positive profile must admit the fixed bytes before creation
        // and use the exact-path reader for every later XML original observation.
        private static let androidVerificationResourceName = "android-positive-verification-v1"
        private static let androidVerificationPath = "project/gradle/verification-metadata.xml"
        private static let androidVerificationLength = 90_045
        private static let androidVerificationSHA256 = "5d00856c785363da964e00da72ad38571cfd088da915ebe86cf20640bb1c7545"

        private func androidVerificationResource() throws -> Data {
            try Self.need(closeErrors.isEmpty, "an earlier consuming close failed")
            let bundle = Bundle(for: NormalAppUITests.self)
            guard let parentURL = bundle.resourceURL,
                  let url = bundle.url(forResource: Self.androidVerificationResourceName, withExtension: "xml"),
                  parentURL.isFileURL && url.isFileURL,
                  url.lastPathComponent == Self.androidVerificationResourceName + ".xml",
                  url.deletingLastPathComponent().path == parentURL.path else {
                throw Refusal.condition("fixture: fixed Android XML resource absent or misplaced")
            }
            let name = Self.androidVerificationResourceName + ".xml"
            let parent = open(parentURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            try Self.need(parent >= 0, "Android XML resource parent open failed")
            var resource: Int32?
            let data: Data
            do {
                let parentBefore = try Self.facts(parent)
                var parentNamedBefore = stat()
                try Self.need(lstat(parentURL.path, &parentNamedBefore) == 0
                    && parentBefore == StatFacts(parentNamedBefore)
                    && parentBefore.mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
                    && parentBefore.uid == getuid() && parentBefore.gid == getgid()
                    && parentBefore.mode & 0o7022 == 0 && parentBefore.flags == 0,
                    "Android XML resource parent shape or binding")
                let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                try Self.need(fd >= 0, "Android XML resource open failed")
                resource = fd // Adopt before the first fallible leaf observation.
                let before = try Self.facts(fd)
                try Self.need(before == Self.named(parent, name)
                    && before.mode & mode_t(S_IFMT) == mode_t(S_IFREG) && before.links == 1
                    && before.uid == getuid() && before.gid == getgid()
                    && before.mode & 0o7022 == 0 && before.flags == 0
                    && before.device == parentBefore.device && before.bytes == Self.androidVerificationLength,
                    "Android XML resource shape, binding or exact length")
                var body = Data(), buffer = [UInt8](repeating: 0, count: 4096)
                while true {
                    let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
                    try Self.need(count >= 0, "Android XML resource read failed")
                    if count == 0 { break }
                    try Self.need(body.count + count <= Self.androidVerificationLength, "Android XML resource read limit")
                    body.append(contentsOf: buffer.prefix(count))
                }
                try Self.need(body.count == Self.androidVerificationLength
                    && SHA256.hash(data: body).map({ String(format: "%02x", $0) }).joined() == Self.androidVerificationSHA256
                    && before == Self.facts(fd) && before == Self.named(parent, name),
                    "Android XML resource content or original changed")
                var parentNamedAfter = stat()
                try Self.need(lstat(parentURL.path, &parentNamedAfter) == 0
                    && parentBefore == Self.facts(parent) && parentBefore == StatFacts(parentNamedAfter),
                    "Android XML resource parent changed")
                data = body
            } catch {
                if let fd = resource, Darwin.close(fd) != 0 { closeErrors.append("android-xml-resource-close") }
                if Darwin.close(parent) != 0 { closeErrors.append("android-xml-parent-close") }
                throw error // Consuming close failures cannot replace this primary failure.
            }
            if let fd = resource, Darwin.close(fd) != 0 { closeErrors.append("android-xml-resource-close") }
            if Darwin.close(parent) != 0 { closeErrors.append("android-xml-parent-close") }
            try Self.need(closeErrors.isEmpty, "Android XML resource consuming close failed")
            return data
        }

        private func readAndroidVerificationOriginal() throws -> File {
            try Self.need(closeErrors.isEmpty, "an earlier consuming close failed")
            guard let expected = originals[Self.androidVerificationPath],
                  let original = directories["project/gradle"] else {
                throw Refusal.condition("fixture: fixed Android XML original was not admitted")
            }
            try Self.need(expected.count == Self.androidVerificationLength
                && SHA256.hash(data: expected).map({ String(format: "%02x", $0) }).joined() == Self.androidVerificationSHA256,
                "admitted Android XML pin differs")
            let observed = try readLeaf(original, name: "verification-metadata.xml", privateOnly: true,
                                        limit: Self.androidVerificationLength)
            // readLeaf consumes its temporary FD, including when observation fails.
            try Self.need(closeErrors.isEmpty, "Android XML original consuming close failed")
            try checkDirectory(original)
            try Self.need(observed.bytes.count == Self.androidVerificationLength && observed.bytes == expected,
                          "Android XML original content differs")
            return observed
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
        // One ordinary unsigned archive's post-terminal namespace observation.
        // Archive descendants are opaque: the product's original result already
        // performed structural/dSYM inspection. This grants no deletion authority.
        static let iosUnsignedPaths: Set<String> = [config, version, "project/.gitignore", "project/keep.txt",
            "project/ios/MRKObserved.xcodeproj/project.pbxproj",
            "project/ios/MRKObserved.xcodeproj/xcshareddata/xcschemes/MRKObserved.xcscheme",
            "project/ios/MRKObserved.xcodeproj/project.xcworkspace/contents.xcworkspacedata",
            "project/ios/MRKObserved/main.m", "project/ios/MRKObserved/Info.plist"]
        struct IOSArchiveIdentity: Equatable {
            let operationID: String
            let ownerGeneration: String
            init(operationID: String, ownerGeneration: String) throws {
                try LocalFixture.need([operationID, ownerGeneration].allSatisfy {
                    $0.utf8.count == 32 && $0.range(of: #"^[0-9a-f]{32}$"#, options: .regularExpression) != nil
                }, "iOS original identity shape")
                self.operationID = operationID; self.ownerGeneration = ownerGeneration
            }
        }
        private var iosUnsignedProfile = false
        private var iosIdentity: IOSArchiveIdentity?
        private var iosStarted = false
        private var iosCompleted = false
        private var iosClosing = false
        private var iosDirectories: [Directory] = []
        func beginIOSArchiveObservation(_ identity: IOSArchiveIdentity, check: () throws -> Void) throws {
            try check()
            try Self.need(iosUnsignedProfile && androidOutput == nil && iosIdentity == nil
                && iosDirectories.isEmpty && !iosStarted && !iosCompleted
                && acceptedStages.isEmpty && Set(current.keys) == Self.iosUnsignedPaths,
                "iOS fixed profile or repeated review")
            try assertUnchanged() // Includes absence of .mobile-release before the one Start.
            try check()
            iosIdentity = identity
        }
        func confirmIOSArchiveStart(_ identity: IOSArchiveIdentity, check: () throws -> Void) throws {
            try check()
            try Self.need(iosIdentity == identity && !iosStarted && !iosCompleted, "iOS original Start identity or state")
            try assertUnchanged()
            try check()
            iosStarted = true
        }
        private func checkIOSDirectories(_ identity: IOSArchiveIdentity, check: () throws -> Void) throws {
            try check()
            try Self.need(iosIdentity == identity && iosStarted && iosDirectories.count == 4,
                          "iOS terminal original identity or directory count")
            for original in iosDirectories { try check(); try checkDirectory(original) }
            for (index, names) in [Set(["desktop-ios-archive"]), Set([identity.operationID]), Set(["archive.xcarchive"])].enumerated() {
                try Self.need(try children(iosDirectories[index]) == names, "iOS settled top-level output roster")
            }
            // Deliberately never enumerate, open or hash archive descendants.
            for original in iosDirectories.reversed() { try checkDirectory(original) }
            try Self.need(closeErrors.isEmpty, "iOS output enumeration consuming close")
            try check()
        }
        func finishIOSArchiveObservation(_ identity: IOSArchiveIdentity, check: () throws -> Void) throws {
            try check()
            try Self.need(iosUnsignedProfile && iosIdentity == identity && iosStarted && !iosCompleted
                && iosDirectories.isEmpty && acceptedStages.isEmpty, "iOS terminal original identity or state")
            guard var parent = directories["project"] else { throw Refusal.condition("fixture: iOS input project absent") }
            let device = parent.facts.device
            for (index, name) in [".mobile-release", "desktop-ios-archive", identity.operationID, "archive.xcarchive"].enumerated() {
                try check(); try checkDirectory(parent)
                let original = try adoptDirectory(openat(parent.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                                                  parent: parent.fd, name: name)
                iosDirectories.append(original) // Already adopted before any subsequent refusal.
                try Self.need(original.facts.uid == getuid() && original.facts.device == device && original.facts.flags == 0
                    && (index < 3 ? original.facts.mode & 0o7777 == 0o700 : original.facts.mode & 0o7022 == 0),
                    "iOS output original mode owner or filesystem")
                // Xcode archive group/mode is not a toolkit-created 0700 root.
                parent = original
            }
            try checkIOSDirectories(identity, check: check)
            // Entered only after the caller's current typed complete result AND
            // all four originals/exact three immediate rosters above. No running
            // output or pathname alone can enable checkRoster's one exception.
            iosCompleted = true
            try assertUnchanged()
            try checkIOSDirectories(identity, check: check)
        }
        func assertIOSArchiveClosure(_ identity: IOSArchiveIdentity, check: () throws -> Void) throws {
            try Self.need(iosCompleted && iosIdentity == identity && !iosClosing, "iOS output closure is not terminal")
            try checkIOSDirectories(identity, check: check)
            try assertUnchanged()
            try check()
        }
        func closeIOSArchiveOriginals(_ identity: IOSArchiveIdentity, check: () throws -> Void) throws {
            var primary: Error?
            do { try assertIOSArchiveClosure(identity, check: check) } catch { primary = error }
            iosClosing = true
            do { try closeOriginals() } catch { if primary == nil { primary = error } }
            iosIdentity = nil; iosStarted = false; iosCompleted = false; iosClosing = false
            iosDirectories.removeAll()
            // This is the SAME original clock after all consuming closes. A late
            // failure cannot publish success or mask an earlier observation error.
            do { try check() } catch { if primary == nil { primary = error } }
            if let primary { throw primary }
        }

        // Fixed positive Android output custody; only the dedicated signed profile enters it.
        // Call begin at the real parsed review, start immediately before the ONE
        // Start action, and finish only after the same real terminal result says
        // complete / work removed / artifacts retained-local-result. The caller's
        // check closure is the existing original case deadline/owner check.
        struct AndroidBuildIdentity: Equatable {
            let operationID: String
            let ownerGeneration: String
            init(operationID: String, ownerGeneration: String) throws {
                for value in [operationID, ownerGeneration] {
                    try LocalFixture.need(value.range(of: #"^[0-9a-f]{32}$"#, options: .regularExpression) != nil,
                                          "Android current build identity shape")
                }
                self.operationID = operationID; self.ownerGeneration = ownerGeneration
            }
        }
        struct AndroidOutputSummary: Equatable {
            let entries: Int
            let nameBytes: Int
            let logicalBytes: Int64
            let moduleBytes: Int64
            let censusSHA256: String
            let artifactSHA256: String
            let artifactBytes: Int64
        }
        private enum AndroidOutputStage: Equatable { case reviewed, running, complete }
        private struct AndroidOutputState {
            let identity: AndroidBuildIdentity
            var stage: AndroidOutputStage
            var summary: AndroidOutputSummary?
        }
        private var androidOutput: AndroidOutputState?
        private var androidClosing = false
        private static let androidOutputRoots = ["project/app/build", "project/.mobile-release", "project/build"]
        private static let androidAAB = "project/app/build/outputs/bundle/release/app-release.aab"
        private static let androidReport = "project/build/reports/problems/problems-report.html"
        private static let androidEntryLimit = 100_000
        private static let androidNameLimit = 2 * 1024 * 1024
        private static let androidRelativeLimit = 2048
        private static let androidDepthLimit = 32
        private static let androidAABLimit: Int64 = 64 * 1024 * 1024
        private static let androidModuleLimit: Int64 = 1024 * 1024 * 1024
        private static let androidLogicalLimit: Int64 = 2 * 1024 * 1024 * 1024
        private static let androidReportLimit: Int64 = 16 * 1024 * 1024

        private func androidInputPost(_ check: () throws -> Void) throws {
            try check()
            try Self.need(closeErrors.isEmpty, "Android earlier consuming close failed")
            for directory in anchors { try checkDirectory(directory) }
            for directory in directories.values { try checkDirectory(directory) }
            for path in current.keys.sorted() {
                try check()
                let old = current[path]!
                let observed: File
                if path == Self.androidVerificationPath { observed = try readAndroidVerificationOriginal() }
                else { observed = try read(path) }
                try Self.need(old.bytes == observed.bytes && old.facts == observed.facts,
                              "Android immutable input changed")
            }
            try Self.need(closeErrors.isEmpty, "Android input consuming close failed")
        }
        private func androidInputRoster(outputsMayExist: Bool) throws {
            let leaves = Set(current.keys), expectedDirectories = Set(Self.ancestors(leaves))
            try Self.need(Set(directories.keys) == expectedDirectories, "Android input directory roster")
            for path in expectedDirectories.sorted() {
                guard let original = directories[path] else { throw Refusal.condition("fixture: Android input parent absent") }
                let prefix = path.isEmpty ? "" : path + "/"
                let expected = Set(leaves.union(expectedDirectories).compactMap { item -> String? in
                    guard item.hasPrefix(prefix), item != path else { return nil }
                    let rest = String(item.dropFirst(prefix.count)); return rest.contains("/") ? nil : rest
                })
                let admittedOutputs = Set(Self.androidOutputRoots.compactMap { item -> String? in
                    let (parent, name) = Self.parts(item); return outputsMayExist && parent == path ? name : nil
                })
                let actual = try children(original)
                try Self.need(actual.subtracting(admittedOutputs) == expected,
                              "Android unexpected input-adjacent output")
            }
            try Self.need(closeErrors.isEmpty, "Android input roster consuming close failed")
        }
        func beginAndroidOutputObservation(_ identity: AndroidBuildIdentity, check: () throws -> Void) throws {
            try Self.need(androidOutput == nil && (androidPositiveProfile
                ? acceptedStages == ["android-public-certificate"] : acceptedStages.isEmpty),
                          "Android output observation repeated or mixed with Save")
            // Unconfigured ordinary profiles cannot activate this seam. Future
            // positive input admission owns actual reviewed project/locks/keys;
            // this is not an alternate input materializer or a DATA nomination.
            try Self.need(current[Self.androidVerificationPath] != nil
                && current["project/buildscript-gradle.lockfile"] != nil
                && current["project/app/gradle.lockfile"] != nil
                && current["project/app/src/main/AndroidManifest.xml"] != nil,
                "Android positive input prerequisites absent")
            try androidInputPost(check)
            try androidInputRoster(outputsMayExist: false)
            for path in Self.androidOutputRoots {
                let (parent, name) = Self.parts(path)
                guard let original = directories[parent] else { throw Refusal.condition("fixture: Android output parent absent") }
                var s = stat(); let result = fstatat(original.fd, name, &s, AT_SYMLINK_NOFOLLOW), code = errno
                try Self.need(result == -1 && code == ENOENT, "Android output existed before review")
            }
            try check()
            androidOutput = AndroidOutputState(identity: identity, stage: .reviewed, summary: nil)
        }
        func confirmAndroidStart(_ identity: AndroidBuildIdentity, check: () throws -> Void) throws {
            guard var state = androidOutput, state.stage == .reviewed, state.identity == identity else {
                throw Refusal.condition("fixture: Android original Start identity or state differs")
            }
            try androidInputPost(check); try androidInputRoster(outputsMayExist: false); try check()
            state.stage = .running; androidOutput = state
        }
        func assertAndroidRunning(_ identity: AndroidBuildIdentity, check: () throws -> Void) throws {
            guard let state = androidOutput, state.stage == .running, state.identity == identity else {
                throw Refusal.condition("fixture: Android running original identity differs")
            }
            try androidInputPost(check)
            // Work is still changing. No output census or closed claim here.
        }

        private static func androidOutputNamed(_ parent: Int32, _ name: String) throws -> StatFacts {
            var value = stat()
            try need(fstatat(parent, name, &value, AT_SYMLINK_NOFOLLOW) == 0,
                     "Android output named binding unavailable")
            return StatFacts(value)
        }
        private func androidOutputDirectoryPost(_ original: Directory) throws {
            let observed = try Self.facts(original.fd)
            try Self.need(original.facts.sameDirectory(observed), "Android output original directory changed")
            if let parent = original.parent {
                try Self.need(observed.sameDirectory(Self.androidOutputNamed(parent, original.name)),
                              "Android output named directory changed")
            }
        }
        private struct AndroidCensus {
            var entries = 0
            var nameBytes = 0
            var logicalBytes: Int64 = 0
            var moduleBytes: Int64 = 0
            var identities: Set<String> = []
            var digest = SHA256()
            var projectAAB = false
            var artifactSHA256: String?
            var artifactBytes: Int64?
        }
        private func androidOutputNames(_ directory: Directory, path: String, entryLimit: Int,
                                        census: inout AndroidCensus, check: () throws -> Void) throws -> [String] {
            try check(); try androidOutputDirectoryPost(directory)
            let before = try Self.facts(directory.fd)
            let fd = openat(directory.fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            try Self.need(fd >= 0, "Android census enumeration open")
            guard let stream = fdopendir(fd) else {
                if Darwin.close(fd) != 0 { closeErrors.append("android-census-open-close") }
                throw Refusal.condition("fixture: Android census enumeration conversion")
            }
            var names: [String] = [], canonical: Set<String> = []
            do {
                while true {
                    try check(); errno = 0
                    guard let entry = readdir(stream) else {
                        try Self.need(errno == 0, "Android census enumeration failed"); break
                    }
                    let length = Int(entry.pointee.d_namlen)
                    try Self.need(length > 0 && length <= Int(NAME_MAX), "Android output name length")
                    let bytes = withUnsafePointer(to: &entry.pointee.d_name) {
                        $0.withMemoryRebound(to: UInt8.self, capacity: Int(NAME_MAX) + 1) {
                            Array(UnsafeBufferPointer(start: $0, count: length))
                        }
                    }
                    guard let name = String(bytes: bytes, encoding: .utf8), !bytes.contains(0) else {
                        throw Refusal.condition("fixture: Android output name encoding")
                    }
                    if name == "." || name == ".." { continue }
                    let relative = path + "/" + name
                    try Self.need(!name.contains("/") && !name.contains("\\")
                        && !name.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 })
                        && relative.utf8.count <= Self.androidRelativeLimit
                        && census.entries < entryLimit && census.nameBytes <= Self.androidNameLimit - relative.utf8.count,
                        "Android output census name or entry bound")
                    let key = name.precomposedStringWithCanonicalMapping.lowercased()
                    try Self.need(canonical.insert(key).inserted, "Android output canonical duplicate")
                    census.entries += 1; census.nameBytes += relative.utf8.count; names.append(name)
                }
                try Self.need(before == Self.facts(directory.fd), "Android output roster changed")
                try androidOutputDirectoryPost(directory)
            } catch {
                if closedir(stream) != 0 { closeErrors.append("android-census-close") }
                throw error
            }
            if closedir(stream) != 0 { closeErrors.append("android-census-close") }
            try Self.need(closeErrors.isEmpty, "Android output enumeration consuming close failed")
            return names.sorted()
        }
        private func androidOutputWalk(_ parent: Directory, name: String, path: String, depth: Int,
                                       identity: AndroidBuildIdentity, entryLimit: Int,
                                       census: inout AndroidCensus, check: () throws -> Void) throws {
            try check(); try androidOutputDirectoryPost(parent)
            try Self.need(depth <= Self.androidDepthLimit, "Android output depth bound")
            let fd = openat(parent.fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            try Self.need(fd >= 0, "Android output original open")
            do {
                let before = try Self.facts(fd), kind = before.mode & mode_t(S_IFMT)
                try Self.need(before == Self.androidOutputNamed(parent.fd, name)
                    && (kind == mode_t(S_IFDIR) || kind == mode_t(S_IFREG))
                    && before.uid == getuid() && before.gid == getgid() && before.flags == 0
                    && before.device == parent.facts.device && before.mode & 0o7022 == 0,
                    "Android output type owner mode or binding")
                let originalKey = String(before.device) + ":" + String(before.inode)
                try Self.need(census.identities.insert(originalKey).inserted, "Android output original alias")
                let artifact = "project/.mobile-release/desktop-android-build/" + identity.operationID + "/artifacts/app-release.aab"
                if kind == mode_t(S_IFDIR) {
                    let directory = Directory(fd: fd, parent: parent.fd, name: name, facts: before)
                    let names = try androidOutputNames(directory, path: path, entryLimit: entryLimit, census: &census, check: check)
                    if path == "project/.mobile-release" {
                        try Self.need(names == ["desktop-android-build"], "Android private root output roster")
                    } else if path == "project/.mobile-release/desktop-android-build" {
                        try Self.need(names == [identity.operationID], "Android operation output roster")
                    } else if path == "project/.mobile-release/desktop-android-build/" + identity.operationID {
                        try Self.need(names == ["artifacts"], "Android work or journal remains")
                    } else if path == "project/.mobile-release/desktop-android-build/" + identity.operationID + "/artifacts" {
                        try Self.need(names == ["app-release.aab"], "Android retained artifact roster")
                    } else if path == "project/build" {
                        try Self.need(names == ["reports"], "Android root build output roster")
                    } else if path == "project/build/reports" {
                        try Self.need(names == ["problems"], "Android report parent roster")
                    } else if path == "project/build/reports/problems" {
                        try Self.need(names == ["problems-report.html"], "Android report output roster")
                    } else {
                        try Self.need(path == "project/app/build" || path.hasPrefix("project/app/build/"),
                                      "Android unrecognized output directory")
                    }
                    if path.hasPrefix("project/.mobile-release") {
                        try Self.need(before.mode & 0o7777 == 0o700, "Android private output directory mode")
                    }
                    if path == "project/app/build/outputs/bundle/release" {
                        try Self.need(names.filter { $0.hasSuffix(".aab") } == ["app-release.aab"], "Android project AAB candidate roster")
                    }
                    for child in names {
                        try androidOutputWalk(directory, name: child, path: path + "/" + child, depth: depth + 1,
                                              identity: identity, entryLimit: entryLimit, census: &census, check: check)
                    }
                } else {
                    try Self.need(before.links == 1 && before.bytes >= 0, "Android output regular leaf shape")
                    let size = Int64(before.bytes)
                    try Self.need(size <= Self.androidLogicalLimit - census.logicalBytes, "Android output total byte bound")
                    census.logicalBytes += size
                    if path.hasPrefix("project/app/build/") {
                        try Self.need(size <= Self.androidModuleLimit - census.moduleBytes, "Android module output byte bound")
                        census.moduleBytes += size
                    } else {
                        try Self.need(path == artifact || path == Self.androidReport, "Android unrecognized output leaf")
                    }
                    if path == Self.androidReport { try Self.need(size <= Self.androidReportLimit, "Android report byte bound") }
                    if path == Self.androidAAB || path == artifact {
                        try Self.need(size > 0 && size <= Self.androidAABLimit, "Android AAB byte bound")
                        if path == artifact { try Self.need(before.mode & 0o7777 == 0o600, "Android captured AAB mode") }
                        var hash = SHA256(), total: Int64 = 0, buffer = [UInt8](repeating: 0, count: 64 * 1024)
                        while true {
                            try check()
                            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
                            try Self.need(count >= 0, "Android AAB original read")
                            if count == 0 { break }
                            try Self.need(Int64(count) <= Self.androidAABLimit - total, "Android AAB read bound")
                            total += Int64(count); hash.update(data: Data(buffer.prefix(count)))
                        }
                        try Self.need(total == size, "Android AAB exact EOF")
                        let digest = hash.finalize().map { String(format: "%02x", $0) }.joined()
                        if path == artifact { census.artifactSHA256 = digest; census.artifactBytes = size }
                        else { census.projectAAB = true } // Signed and unsigned hashes need not equal.
                    }
                }
                try Self.need(before == Self.facts(fd) && before == Self.androidOutputNamed(parent.fd, name), "Android output original POST")
                try androidOutputDirectoryPost(parent); try check()
                let row = try JSONSerialization.data(withJSONObject: [path, Self.wireFacts(before)], options: [.sortedKeys, .withoutEscapingSlashes])
                census.digest.update(data: row); census.digest.update(data: Data([10]))
            } catch {
                if Darwin.close(fd) != 0 { closeErrors.append("android-output-close") }
                throw error
            }
            if Darwin.close(fd) != 0 { closeErrors.append("android-output-close") }
            try Self.need(closeErrors.isEmpty, "Android output consuming close failed")
        }
        private func scanAndroidOutputs(_ identity: AndroidBuildIdentity, entryLimit: Int = LocalFixture.androidEntryLimit,
                                        check: () throws -> Void) throws -> AndroidOutputSummary {
            // Tests may LOWER only this existing finite limit; no production
            // caller can increase the fixed ceiling or change roots/policy.
            try Self.need(entryLimit > 0 && entryLimit <= Self.androidEntryLimit, "Android census limit selection")
            try androidInputPost(check); try androidInputRoster(outputsMayExist: true)
            var census = AndroidCensus()
            for path in Self.androidOutputRoots {
                let (parent, name) = Self.parts(path)
                guard let original = directories[parent] else { throw Refusal.condition("fixture: Android output parent absent") }
                var s = stat(); let result = fstatat(original.fd, name, &s, AT_SYMLINK_NOFOLLOW), code = errno
                if path == "project/build" && result == -1 && code == ENOENT { continue }
                try Self.need(result == 0 && StatFacts(s).mode & mode_t(S_IFMT) == mode_t(S_IFDIR), "Android output root absent or type")
                try Self.need(census.entries < entryLimit && census.nameBytes <= Self.androidNameLimit - path.utf8.count,
                              "Android root census bound")
                census.entries += 1; census.nameBytes += path.utf8.count
                try androidOutputWalk(original, name: name, path: path, depth: 0, identity: identity,
                                      entryLimit: entryLimit, census: &census, check: check)
            }
            try androidInputPost(check); try androidInputRoster(outputsMayExist: true); try check()
            guard census.projectAAB, let digest = census.artifactSHA256, let size = census.artifactBytes else {
                throw Refusal.condition("fixture: Android required AAB observations absent")
            }
            return AndroidOutputSummary(entries: census.entries, nameBytes: census.nameBytes,
                logicalBytes: census.logicalBytes, moduleBytes: census.moduleBytes,
                censusSHA256: census.digest.finalize().map { String(format: "%02x", $0) }.joined(),
                artifactSHA256: digest, artifactBytes: size)
        }
        func finishAndroidOutputObservation(_ identity: AndroidBuildIdentity, artifactBytes: Int64,
                                            artifactSHA256: String, check: () throws -> Void) throws -> AndroidOutputSummary {
            guard var state = androidOutput, state.stage == .running, state.identity == identity else {
                throw Refusal.condition("fixture: Android terminal original identity differs")
            }
            try Self.need(artifactBytes > 0 && artifactBytes <= Self.androidAABLimit
                && artifactSHA256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil,
                "Android parsed terminal artifact shape")
            let result = try scanAndroidOutputs(identity, check: check)
            try Self.need(result.artifactBytes == artifactBytes && result.artifactSHA256 == artifactSHA256,
                          "Android current terminal artifact differs")
            try check(); state.stage = .complete; state.summary = result; androidOutput = state
            return result
        }
        func assertAndroidOutputClosure(_ identity: AndroidBuildIdentity, check: () throws -> Void) throws {
            guard let state = androidOutput, state.stage == .complete, state.identity == identity, let summary = state.summary else {
                throw Refusal.condition("fixture: Android output closure is not terminal")
            }
            try Self.need(try scanAndroidOutputs(identity, check: check) == summary, "Android retained output changed")
        }
        func closeAndroidOriginals(_ identity: AndroidBuildIdentity, check: () throws -> Void) throws {
            var primary: Error?
            do { try assertAndroidOutputClosure(identity, check: check); androidClosing = true }
            catch { primary = error }
            do { try closeOriginals() } catch { if primary == nil { primary = error } }
            // A consuming close may complete late; it cannot inherit the earlier
            // census clock observation. Always check, without replacing primary.
            do { try check() } catch { if primary == nil { primary = error } }
            androidOutput = nil; androidClosing = false
            if let primary { throw primary }
        }
        // End fixed positive Android output custody.

        // Native DATA-only regression of the same scanner; no app, Gradle,
        // project command, signing material, product lease or success receipt.
        static func exerciseAndroidOutputCustodyData() throws {
            let started = ProcessInfo.processInfo.systemUptime
            var last = started
            func check() throws {
                let now = ProcessInfo.processInfo.systemUptime
                try need(now.isFinite && now >= last && now - started < 30, "Android output DATA case deadline")
                last = now
            }
            let identity = try AndroidBuildIdentity(operationID: String(repeating: "a", count: 32),
                                                     ownerGeneration: String(repeating: "b", count: 32))
            for scenario in ["valid", "late-close", "extra-operation", "work", "journal", "project-cache", "extra-artifact",
                             "symlink", "hardlink", "depth", "mode", "input", "wrong-result", "identity", "repeated-start",
                             "ios-valid", "ios-work", "ios-extra-operation", "ios-foreign-output", "ios-symlink",
                             "ios-replacement", "ios-partial-open", "ios-late-close", "ios-input"] {
                try check()
                let fixture = LocalFixture()
                let temporary = open("/private/tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                try need(temporary >= 0, "Android output DATA temporary original")
                var template = Array("/private/tmp/mrk-normal-output-data-XXXXXX".utf8CString)
                let root = template.withUnsafeMutableBufferPointer { buffer -> String? in
                    guard let made = mkdtemp(buffer.baseAddress!) else { return nil }
                    return String(cString: made)
                }
                guard let root else {
                    _ = Darwin.close(temporary) // Creation failure remains primary; consuming close is not retried.
                    throw Refusal.condition("fixture: Android output DATA private root creation")
                }
                fixture.rootPath = root
                let rootName = String(fixture.rootPath.dropFirst("/private/tmp/".count))
                var createdRoot = stat()
                let rootNamed = fstatat(temporary, rootName, &createdRoot, AT_SYMLINK_NOFOLLOW)
                var cleanupFacts: StatFacts? = rootNamed == 0 ? StatFacts(createdRoot) : nil
                let cleanupRoot = openat(temporary, rootName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                var created: [String] = []
                var cleanupRows: [String: StatFacts] = [:]
                var primary: Error?
                func parent(_ path: String) throws -> (Int32, String, [Int32]) {
                    let parts = path.split(separator: "/").map(String.init)
                    var fd = cleanupRoot, adopted: [Int32] = [], relative = ""
                    do {
                        for part in parts.dropLast() {
                            let next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                            try need(next >= 0, "Android output DATA cleanup parent")
                            adopted.append(next)
                            relative = relative.isEmpty ? part : relative + "/" + part
                            guard let expected = cleanupRows[relative] else {
                                throw Refusal.condition("fixture: Android DATA original parent row absent")
                            }
                            try need(expected.sameDirectory(facts(next)) && expected.sameDirectory(named(fd, part)),
                                     "Android DATA original parent replaced")
                            fd = next
                        }
                        return (fd, parts.last!, adopted)
                    } catch {
                        for original in adopted.reversed() { _ = Darwin.close(original) }
                        throw error
                    }
                }
                func closeTemporary(_ values: [Int32]) throws {
                    var failed = false
                    for fd in values.reversed() { if Darwin.close(fd) != 0 { failed = true } }
                    try need(!failed, "Android output DATA temporary consuming close")
                }
                func makeDirectory(_ path: String, input: Bool) throws {
                    let (parentFD, name, opened) = try parent(path)
                    do {
                        try need(mkdirat(parentFD, name, 0o700) == 0, "Android output DATA mkdir")
                        let facts = try named(parentFD, name)
                        created.append(path); cleanupRows[path] = facts
                        if input {
                            let (parentPath, _) = parts(path)
                            guard let original = fixture.directories[parentPath] else {
                                throw Refusal.condition("fixture: Android DATA input parent missing")
                            }
                            fixture.directories[path] = try fixture.adoptDirectory(
                                openat(original.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                                parent: original.fd, name: name)
                        }
                    } catch { try? closeTemporary(opened); throw error }
                    try closeTemporary(opened)
                }
                func makeFile(_ path: String, _ bytes: Data, input: Bool = false) throws {
                    let (parentFD, name, opened) = try parent(path)
                    var original: Int32?
                    do {
                        let fd = openat(parentFD, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
                        try need(fd >= 0, "Android output DATA create leaf")
                        original = fd; created.append(path)
                        cleanupRows[path] = try facts(fd)
                        try bytes.withUnsafeBytes { raw in
                            var offset = 0
                            while offset < raw.count {
                                try check()
                                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                                try need(count > 0, "Android output DATA leaf write"); offset += count
                            }
                        }
                        cleanupRows[path] = try facts(fd)
                        if input {
                            fixture.originals[path] = bytes
                            fixture.current[path] = try path == androidVerificationPath
                                ? fixture.readAndroidVerificationOriginal() : fixture.read(path)
                        }
                    } catch {
                        if let fd = original { _ = Darwin.close(fd) }
                        try? closeTemporary(opened); throw error
                    }
                    var failed = false
                    if let fd = original, Darwin.close(fd) != 0 { failed = true }
                    do { try closeTemporary(opened) } catch { failed = true }
                    try need(!failed, "Android output DATA creation consuming close")
                }
                func refused(_ reason: String, _ body: () throws -> Void) throws {
                    var observed = false
                    do { try body() }
                    catch let failure as Refusal {
                        switch failure {
                        case .condition(let message):
                            guard message == "fixture: " + reason else { throw failure }
                            observed = true
                        }
                    }
                    try need(observed, "Android output DATA exact refusal missing")
                }
                do {
                    try need(cleanupRoot >= 0, "Android output DATA cleanup original")
                    guard let createdFacts = cleanupFacts else { throw Refusal.condition("fixture: Android DATA created root facts absent") }
                    let initialRoot = try initializeNewPrivateRootGroup(cleanupRoot, parent: temporary, name: rootName, created: createdFacts)
                    cleanupFacts = initialRoot // Only a verified transition may become the cleanup baseline.
                    try need(initialRoot.mode & 0o7777 == 0o700, "Android output DATA private original root mode differs")
                    try need(initialRoot.uid == getuid(), "Android output DATA private original root uid differs")
                    try need(initialRoot.gid == getgid(), "Android output DATA private original root gid differs")
                    try need(initialRoot.flags == 0, "Android output DATA private original root flags differ")
                    try need(initialRoot.mode & mode_t(S_IFMT) == mode_t(S_IFDIR), "Android output DATA private original root kind differs")
                    try need(initialRoot == facts(cleanupRoot), "Android output DATA private original root descriptor differs")
                    try need(initialRoot == named(temporary, rootName), "Android output DATA private original root entry differs")
                    fixture.directories[""] = try fixture.adoptDirectory(
                        openat(temporary, rootName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: temporary, name: rootName)
                    try need(fixture.directories[""]!.facts == initialRoot
                        && initialRoot == facts(cleanupRoot) && initialRoot == named(temporary, rootName),
                        "Android DATA adopted root is not the original")
                    if scenario.hasPrefix("ios-") {
                        // Inert tiny files exercise the real Swift original/namespace
                        // reader, not an Xcode archive or a product result substitute.
                        fixture.iosUnsignedProfile = true
                        for path in ancestors(iosUnsignedPaths) where !path.isEmpty { try makeDirectory(path, input: true) }
                        for path in iosUnsignedPaths.sorted() { try makeFile(path, Data("inert iOS SOURCE DATA\n".utf8), input: true) }
                        let ios = try IOSArchiveIdentity(operationID: identity.operationID, ownerGeneration: identity.ownerGeneration)
                        try fixture.beginIOSArchiveObservation(ios, check: check)
                        try fixture.confirmIOSArchiveStart(ios, check: check)
                        let operation = "project/.mobile-release/desktop-ios-archive/" + ios.operationID
                        for path in ["project/.mobile-release", "project/.mobile-release/desktop-ios-archive", operation] {
                            try makeDirectory(path, input: false)
                        }
                        let archive = operation + "/archive.xcarchive"
                        if scenario == "ios-symlink" {
                            let (fd, name, opened) = try parent(archive)
                            do {
                                try need(symlinkat("/private/tmp", fd, name) == 0, "iOS DATA symlink setup")
                                created.append(archive); cleanupRows[archive] = try named(fd, name)
                            } catch { try? closeTemporary(opened); throw error }
                            try closeTemporary(opened)
                        } else if scenario != "ios-partial-open" {
                            try makeDirectory(archive, input: false)
                            try makeFile(archive + "/opaque-data", Data([1])) // Not inspected by the production observer.
                        }
                        switch scenario {
                        case "ios-work": try makeDirectory(operation + "/work", input: false)
                        case "ios-extra-operation": try makeDirectory("project/.mobile-release/desktop-ios-archive/" + String(repeating: "c", count: 32), input: false)
                        case "ios-foreign-output": try makeDirectory("project/foreign-output", input: false)
                        case "ios-input":
                            let (fd, name, opened) = try parent("project/keep.txt")
                            do {
                                try need(fchmodat(fd, name, 0o622, 0) == 0, "iOS DATA input mutation")
                                cleanupRows["project/keep.txt"] = try named(fd, name)
                            } catch { try? closeTemporary(opened); throw error }
                            try closeTemporary(opened)
                        default: break
                        }
                        if ["ios-valid", "ios-replacement", "ios-late-close"].contains(scenario) {
                            try fixture.finishIOSArchiveObservation(ios, check: check)
                            try need(fixture.iosDirectories.count == 4 && fixture.descriptors.count == 13,
                                     "iOS DATA fixed original descriptor census")
                            if scenario == "ios-replacement" {
                                let moved = operation + "/retained-archive", (fd, name, opened) = try parent(archive)
                                do {
                                    try need(renameat(fd, name, fd, "retained-archive") == 0, "iOS DATA same-parent replacement setup")
                                    // DATA cleanup follows ONLY its own original rows after
                                    // this explicit mutation, never a production recovery rule.
                                    for old in created.filter({ $0 == archive || $0.hasPrefix(archive + "/") }) {
                                        let next = moved + String(old.dropFirst(archive.count))
                                        cleanupRows[next] = cleanupRows.removeValue(forKey: old)
                                        if let index = created.firstIndex(of: old) { created[index] = next }
                                    }
                                } catch { try? closeTemporary(opened); throw error }
                                try closeTemporary(opened)
                                try makeDirectory(archive, input: false)
                                try refused("directory binding changed") { try fixture.assertIOSArchiveClosure(ios, check: check) }
                            } else if scenario == "ios-late-close" {
                                var reached = false
                                try refused("iOS DATA closed deadline refusal") {
                                    try fixture.closeIOSArchiveOriginals(ios) {
                                        try check()
                                        if fixture.descriptors.isEmpty {
                                            reached = true
                                            throw Refusal.condition("fixture: iOS DATA closed deadline refusal")
                                        }
                                    }
                                }
                                try need(reached && fixture.iosIdentity == nil && fixture.iosDirectories.isEmpty,
                                         "iOS DATA consuming close and late refusal")
                            } else { try fixture.closeIOSArchiveOriginals(ios, check: check) }
                            try need(faccessat(cleanupRoot, archive, F_OK, AT_EACCESS) == 0,
                                     "iOS DATA production observation deleted archive")
                        } else {
                            let reasons = ["ios-work": "iOS settled top-level output roster",
                                "ios-extra-operation": "iOS settled top-level output roster",
                                "ios-foreign-output": "unexpected owned output under project",
                                "ios-symlink": "directory open failed", "ios-partial-open": "directory open failed",
                                "ios-input": "leaf shape/mode/limit"]
                            guard let reason = reasons[scenario] else { throw Refusal.condition("fixture: iOS DATA scenario unmapped") }
                            try refused(reason) { try fixture.finishIOSArchiveObservation(ios, check: check) }
                            if scenario == "ios-partial-open" {
                                try need(fixture.iosDirectories.count == 3 && fixture.descriptors.count == 12,
                                         "iOS DATA partial opens not retained")
                            }
                        }
                    } else {
                    for path in ["project", "project/app", "project/app/src", "project/app/src/main", "project/gradle"] {
                        try makeDirectory(path, input: true)
                    }
                    try makeFile("project/app/src/main/AndroidManifest.xml", Data("inert input\n".utf8), input: true)
                    try makeFile("project/buildscript-gradle.lockfile", Data("inert root lock DATA, not nominated\n".utf8), input: true)
                    try makeFile("project/app/gradle.lockfile", Data("inert app lock DATA, not nominated\n".utf8), input: true)
                    try makeFile(androidVerificationPath, fixture.androidVerificationResource(), input: true)
                    try fixture.beginAndroidOutputObservation(identity, check: check)
                    try fixture.confirmAndroidStart(identity, check: check)
                    try fixture.assertAndroidRunning(identity, check: check)
                    if scenario == "repeated-start" {
                        try refused("Android original Start identity or state differs") { try fixture.confirmAndroidStart(identity, check: check) }
                    }
                    let operation = "project/.mobile-release/desktop-android-build/" + identity.operationID
                    for path in ["project/app/build", "project/app/build/outputs", "project/app/build/outputs/bundle",
                                 "project/app/build/outputs/bundle/release", "project/.mobile-release",
                                 "project/.mobile-release/desktop-android-build", operation, operation + "/artifacts",
                                 "project/build", "project/build/reports", "project/build/reports/problems"] {
                        try makeDirectory(path, input: false)
                    }
                    let captured = Data("signed-shaped census DATA, not an actual AAB\n".utf8)
                    try makeFile(androidAAB, Data("different unsigned census DATA\n".utf8))
                    try makeFile(operation + "/artifacts/app-release.aab", captured)
                    try makeFile(androidReport, Data("private HTML is metadata only\n".utf8))
                    let artifactDigest = SHA256.hash(data: captured).map { String(format: "%02x", $0) }.joined()
                    switch scenario {
                    case "extra-operation": try makeDirectory("project/.mobile-release/desktop-android-build/" + String(repeating: "c", count: 32), input: false)
                    case "work": try makeDirectory(operation + "/work", input: false)
                    case "journal": try makeDirectory("project/.mobile-release/build-inputs", input: false)
                    case "project-cache": try makeDirectory("project/.gradle", input: false)
                    case "extra-artifact": try makeFile(operation + "/artifacts/extra.aab", Data([1]))
                    case "symlink":
                        let path = "project/app/build/link", (fd, name, opened) = try parent(path)
                        do {
                            try need(symlinkat("/private/tmp", fd, name) == 0, "Android DATA symlink setup")
                            created.append(path); cleanupRows[path] = try named(fd, name)
                        } catch { try? closeTemporary(opened); throw error }
                        try closeTemporary(opened)
                    case "hardlink":
                        let path = "project/app/build/alias", (fd, name, opened) = try parent(path)
                        do {
                            try need(linkat(cleanupRoot, androidAAB, fd, name, 0) == 0, "Android DATA hardlink setup")
                            created.append(path); cleanupRows[path] = try named(fd, name)
                        } catch { try? closeTemporary(opened); throw error }
                        try closeTemporary(opened)
                    case "depth":
                        var path = "project/app/build"
                        for _ in 1...33 { path += "/d"; try makeDirectory(path, input: false) }
                    case "mode", "input":
                        let path = scenario == "mode" ? androidAAB : "project/app/src/main/AndroidManifest.xml"
                        let (fd, name, opened) = try parent(path)
                        do {
                            try need(fchmodat(fd, name, 0o622, 0) == 0, "Android DATA mode mutation")
                            cleanupRows[path] = try named(fd, name)
                        } catch { try? closeTemporary(opened); throw error }
                        try closeTemporary(opened)
                    default: break
                    }
                    if scenario == "valid" || scenario == "late-close" {
                        let census = try fixture.finishAndroidOutputObservation(identity, artifactBytes: Int64(captured.count),
                                                                               artifactSHA256: artifactDigest, check: check)
                        try need(census.entries > 0 && census.logicalBytes > 0, "Android DATA census accounting")
                        try need(try fixture.scanAndroidOutputs(identity, entryLimit: census.entries, check: check) == census,
                                 "Android DATA exact entry limit")
                        try refused("Android output census name or entry bound") { _ = try fixture.scanAndroidOutputs(identity, entryLimit: census.entries - 1, check: check) }
                        try fixture.assertAndroidOutputClosure(identity, check: check)
                        // Real missing-name fstatat failures must remain closed
                        // messages, even with a live held original directory.
                        let hidden = "private-name-not-for-diagnostics"
                        try refused("Android output named binding unavailable") {
                            _ = try androidOutputNamed(cleanupRoot, hidden)
                        }
                        let held = fixture.directories["project/app"]!
                        let moved = Directory(fd: held.fd, parent: held.parent, name: hidden, facts: held.facts)
                        try refused("Android output named binding unavailable") {
                            try fixture.androidOutputDirectoryPost(moved)
                        }
                        if scenario == "late-close" {
                            var closedChecked = false
                            try refused("Android DATA closed deadline refusal") {
                                try fixture.closeAndroidOriginals(identity) {
                                    try check()
                                    if fixture.descriptors.isEmpty {
                                        closedChecked = true
                                        throw Refusal.condition("fixture: Android DATA closed deadline refusal")
                                    }
                                }
                            }
                            try need(closedChecked && fixture.androidOutput == nil && !fixture.androidClosing,
                                     "Android DATA late close did not clear state and refuse")
                        } else { try fixture.closeAndroidOriginals(identity, check: check) }
                        // Outputs survive production close; only this DATA test's
                        // separately held, fixed-roster cleanup below removes them.
                        try need(faccessat(cleanupRoot, operation + "/artifacts/app-release.aab", F_OK, AT_EACCESS) == 0,
                                 "Android DATA production close deleted output")
                    } else if scenario == "repeated-start" {
                        // The second Start was refused above; no successful case is claimed.
                    } else if scenario == "identity" {
                        let wrong = try AndroidBuildIdentity(operationID: String(repeating: "d", count: 32), ownerGeneration: identity.ownerGeneration)
                        try refused("Android terminal original identity differs") { _ = try fixture.finishAndroidOutputObservation(wrong, artifactBytes: Int64(captured.count), artifactSHA256: artifactDigest, check: check) }
                    } else {
                        let reasons = ["extra-operation": "Android operation output roster", "work": "Android work or journal remains",
                            "journal": "Android private root output roster", "project-cache": "Android unexpected input-adjacent output",
                            "extra-artifact": "Android retained artifact roster", "symlink": "Android output original open",
                            "hardlink": "Android output regular leaf shape", "depth": "Android output depth bound",
                            "mode": "Android output type owner mode or binding",
                            "input": "leaf shape/mode/limit", "wrong-result": "Android current terminal artifact differs"]
                        guard let reason = reasons[scenario] else { throw Refusal.condition("fixture: Android DATA scenario unmapped") }
                        try refused(reason) { _ = try fixture.finishAndroidOutputObservation(identity, artifactBytes: Int64(captured.count),
                            artifactSHA256: scenario == "wrong-result" ? String(repeating: "0", count: 64) : artifactDigest, check: check) }
                        if scenario == "wrong-result" {
                            var closedChecked = false
                            try refused("Android output closure is not terminal") {
                                try fixture.closeAndroidOriginals(identity) {
                                    try check()
                                    if fixture.descriptors.isEmpty {
                                        closedChecked = true
                                        throw Refusal.condition("fixture: Android DATA later close refusal")
                                    }
                                }
                            }
                            try need(closedChecked && fixture.androidOutput == nil && !fixture.androidClosing,
                                     "Android DATA primary closure failure was masked or state retained")
                        }
                    }
                    } // Existing Android cases above; iOS adds only a fixed top-level reader.
                } catch { primary = error }
                // Consume production FDs even after every setup/assertion error.
                // Running/refused state deliberately has no successful closure.
                if !fixture.descriptors.isEmpty {
                    fixture.androidOutput = nil // DATA-test teardown only, never an operation result.
                    fixture.iosIdentity = nil // Same DATA-only teardown, no completed iOS result inferred.
                    do { try fixture.closeOriginals() } catch { if primary == nil { primary = error } }
                }
                if cleanupRoot >= 0 {
                    for path in created.reversed() {
                        do {
                            let (fd, name, opened) = try parent(path)
                            do {
                                guard let expected = cleanupRows[path] else { throw Refusal.condition("fixture: Android DATA cleanup row absent") }
                                let observed = try named(fd, name)
                                try need(expected.device == observed.device && expected.inode == observed.inode
                                    && expected.uid == observed.uid && expected.mode & mode_t(S_IFMT) == observed.mode & mode_t(S_IFMT),
                                    "Android DATA cleanup original differs")
                                let directory = observed.mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
                                try need(unlinkat(fd, name, directory ? AT_REMOVEDIR : 0) == 0, "Android DATA fixed original removal")
                            } catch { try? closeTemporary(opened); throw error }
                            try closeTemporary(opened)
                        } catch { if primary == nil { primary = error } }
                    }
                    do {
                        if let expected = cleanupFacts {
                            try need(expected.sameDirectory(facts(cleanupRoot)) && expected.sameDirectory(named(temporary, rootName)),
                                     "Android DATA cleanup root replaced")
                            try need(unlinkat(temporary, rootName, AT_REMOVEDIR) == 0, "Android DATA private root retirement")
                        }
                    } catch { if primary == nil { primary = error } }
                    if Darwin.close(cleanupRoot) != 0 && primary == nil { primary = Refusal.condition("fixture: Android DATA cleanup root close") }
                } else if let expected = cleanupFacts {
                    do {
                        try need(expected.uid == getuid() && expected.mode & 0o7777 == 0o700
                            && expected == named(temporary, rootName), "Android DATA unopened cleanup root differs")
                        try need(unlinkat(temporary, rootName, AT_REMOVEDIR) == 0, "Android DATA unopened private root retirement")
                    } catch { if primary == nil { primary = error } }
                }
                if Darwin.close(temporary) != 0 && primary == nil { primary = Refusal.condition("fixture: Android DATA temporary close") }
                if let primary {
                    print("MRK_MACOS_ANDROID_OUTPUT_DATA_FAILURE=v1;scenario=\(scenario);sample=after-cleanup-attempt;originalFailurePreserved=1")
                    throw primary
                }
                try check()
            }
        }

        // A one-case transfer of observation custody, never a product lease. The
        // original parent still holds these exact files throughout XCTest.
        private var savedVersionPending = false
        private var savedVersionBackup: File?
        private var savedVersionDirectories: [String: StatFacts] = [:]
        private(set) var savedVersionTransaction = ""
        private static let savedVersionJournal = "project/.mobile-release-version"
        private static let savedVersionControls: Set<String> = ["header.json", "plan.json", "commit.pending", "rollback.pending", "old-0", "new-0"]
        private static func wireFacts(_ facts: StatFacts) -> [String] {
            [String(facts.device), String(facts.inode), String(facts.mode), String(facts.uid), String(facts.gid),
             String(facts.links), String(facts.bytes),
             String(Int64(facts.modifiedSeconds) * 1_000_000_000 + Int64(facts.modifiedNanoseconds)),
             String(Int64(facts.changedSeconds) * 1_000_000_000 + Int64(facts.changedNanoseconds)), String(facts.flags)]
        }
        private static func sameSavedVersionMove(_ before: StatFacts, _ after: StatFacts) -> Bool {
            let a = wireFacts(before), b = wireFacts(after)
            return Array(a.prefix(8)) == Array(b.prefix(8)) && a[9] == b[9]
        }
        private func adoptSavedVersion(_ data: Data, temporary: Directory) throws {
            let env = ProcessInfo.processInfo.environment
            guard let path = env["MRK_NORMAL_UI_SAVED_VERSION_FIXTURE"],
                  path.range(of: #"^/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}/normal-ui/saved-version-recovery-fixture\.json$"#,
                             options: .regularExpression) != nil else {
                throw Refusal.condition("fixture: fixed owner-derived recovery handoff missing")
            }
            // Hold every original handoff ancestor; never follow a path supplied
            // by the renderer or use it as a normal-application environment override.
            var parent = try adoptDirectory(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: nil, name: "/")
            anchors.append(parent)
            for name in path.split(separator: "/").dropLast().map(String.init) {
                parent = try adoptDirectory(openat(parent.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: parent.fd, name: name)
                anchors.append(parent)
                try Self.need((parent.facts.uid == 0 || parent.facts.uid == getuid()) && parent.facts.mode & 0o022 == 0,
                              "recovery handoff ancestor policy")
            }
            let handoff = try readLeaf(parent, name: "saved-version-recovery-fixture.json", privateOnly: true, limit: 16 * 1024)
            try Self.need(handoff.bytes.count <= 16 * 1024 && handoff.bytes.last == 10, "recovery handoff bound")
            guard let raw = try JSONSerialization.jsonObject(with: handoff.bytes) as? [String: Any],
                  Set(raw.keys) == Set(["schemaVersion", "scope", "sourceCommit", "sourceInputsSha256", "runtimeManifestSha256",
                      "sourceClosureSha256", "fixtureDataSha256", "producerSha256", "producerFramesSha256", "root",
                      "transactionId", "originalVersionFacts", "directories", "files"]),
                  let schema = raw["schemaVersion"] as? Int, schema == 1,
                  let source = raw["sourceCommit"] as? String,
                  source == env["MRK_NORMAL_UI_HARNESS_SOURCE"], source == env["MRK_NORMAL_UI_APPLICATION_SOURCE"],
                  raw["scope"] as? String == "one-owned-saved-version-recovery-fixture",
                  raw["sourceInputsSha256"] as? String == "fa624512af03437f075f2da10357b3808d1a58c8f36e1db6103bc2abe54150e0",
                  let root = raw["root"] as? String,
                  root.range(of: #"^/private/tmp/mrk-normal-project-[A-Za-z0-9_-]{6,16}$"#, options: .regularExpression) != nil,
                  let transaction = raw["transactionId"] as? String,
                  transaction.range(of: #"^[0-9a-f]{32}$"#, options: .regularExpression) != nil,
                  let oldFacts = raw["originalVersionFacts"] as? [String], oldFacts.count == 10,
                  let directoryFacts = raw["directories"] as? [String: [String]],
                  let fileFacts = raw["files"] as? [String: [String: Any]] else {
                throw Refusal.condition("fixture: closed recovery handoff differs")
            }
            // Parent emits canonical ASCII JSON. Equality also rejects duplicate
            // keys/coerced numeric spellings, without a second permissive parser.
            var canonicalObject = raw
            canonicalObject["schemaVersion"] = 1 // Reject JSON true coercing to NSNumber/Int one.
            let canonical = try JSONSerialization.data(withJSONObject: canonicalObject, options: [.sortedKeys, .withoutEscapingSlashes]) + Data([10])
            try Self.need(canonical == handoff.bytes, "recovery handoff is not the exact canonical document")
            for key in ["runtimeManifestSha256", "sourceClosureSha256", "fixtureDataSha256", "producerSha256", "producerFramesSha256"] {
                guard let digest = raw[key] as? String,
                      digest.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
                    throw Refusal.condition("fixture: recovery handoff digest unavailable")
                }
            }
            let dataDigest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            try Self.need(raw["fixtureDataSha256"] as? String == dataDigest, "recovery handoff bundled DATA differs")
            let paths = Set(originals.keys).subtracting([Self.version]).union(Self.savedVersionControls.map { Self.savedVersionJournal + "/" + $0 })
            let expectedDirectories = Set(Self.ancestors(paths))
            try Self.need(paths.count == 18 && Set(fileFacts.keys) == paths && Set(directoryFacts.keys) == expectedDirectories,
                          "recovery handoff exact ready-journal roster")
            rootPath = root
            let name = String(root.dropFirst("/private/tmp/".count))
            directories[""] = try adoptDirectory(openat(temporary.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: temporary.fd, name: name)
            for path in Self.ancestors(paths) where !path.isEmpty {
                let (parent, name) = Self.parts(path), original = directories[parent]!
                directories[path] = try adoptDirectory(openat(original.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: original.fd, name: name)
            }
            for (path, directory) in directories {
                try Self.need(directory.facts.uid == getuid() && directory.facts.gid == getgid()
                    && directory.facts.mode & 0o7777 == 0o700 && directory.facts.flags == 0
                    && directoryFacts[path] == Self.wireFacts(directory.facts), "recovery directory original differs")
                savedVersionDirectories[path] = directory.facts
            }
            for path in paths.sorted() {
                let observed = try read(path)
                guard let row = fileFacts[path], Set(row.keys) == ["facts", "sha256"],
                      let expectedFacts = row["facts"] as? [String], expectedFacts == Self.wireFacts(observed.facts),
                      let digest = row["sha256"] as? String,
                      digest == SHA256.hash(data: observed.bytes).map({ String(format: "%02x", $0) }).joined() else {
                    throw Refusal.condition("fixture: recovery file original differs")
                }
                let mode: mode_t = path.hasPrefix("sources/") ? 0o644 : 0o600
                try Self.need(observed.facts.mode & 0o7777 == mode && observed.facts.flags == 0
                    && observed.facts.device == directories[""]!.facts.device, "recovery file mode/device differs")
                if let expected = originals[path] { try Self.need(observed.bytes == expected, "recovery unrelated bundled DATA differs") }
                current[path] = observed
            }
            let backup = current[Self.savedVersionJournal + "/old-0"]!
            let backupFacts = Self.wireFacts(backup.facts)
            try Self.need(backup.bytes == originals[Self.version] && Array(oldFacts.prefix(8)) == Array(backupFacts.prefix(8))
                && oldFacts[9] == backupFacts[9]
                && current[Self.savedVersionJournal + "/new-0"]!.bytes == changes["version"]?[Self.version],
                "recovery handoff actual version rename differs")
            savedVersionPending = true
            savedVersionBackup = backup
            savedVersionTransaction = transaction
            try assertUnchanged()
            // Recheck the actual handoff leaf after all admission reads; no reopen
            // as a replacement authority and no permission to delete any fixture.
            let after = try readLeaf(parent, name: "saved-version-recovery-fixture.json", privateOnly: true, limit: 16 * 1024)
            try Self.need(after.bytes == handoff.bytes && after.facts == handoff.facts && closeErrors.isEmpty,
                          "recovery handoff changed during admission")
        }
        func assertSavedVersionPending() throws {
            try Self.need(savedVersionPending && savedVersionBackup != nil, "no original pending version journal")
            try assertUnchanged()
            for (path, original) in savedVersionDirectories {
                try Self.need(original == Self.facts(directories[path]!.fd), "read-only inspection changed a directory")
            }
        }
        func acceptSavedVersionRollback() throws {
            try Self.need(savedVersionPending && acceptedStages.isEmpty, "recovery was repeated or mixed with a Save")
            guard let backup = savedVersionBackup else { throw Refusal.condition("fixture: original backup absent") }
            let restored = try read(Self.version)
            try Self.need(restored.bytes == originals[Self.version] && Self.sameSavedVersionMove(backup.facts, restored.facts),
                          "original version bytes/inode/owner/mode/mtime were not restored")
            for (path, original) in current where !path.hasPrefix(Self.savedVersionJournal + "/") {
                let observed = try read(path)
                try Self.need(original.bytes == observed.bytes && original.facts == observed.facts, "recovery changed unrelated original")
            }
            for (path, original) in savedVersionDirectories where path != Self.savedVersionJournal {
                let observed = try Self.facts(directories[path]!.fd)
                try Self.need(path == "project" || path == "project/release" ? original.sameDirectory(observed) : original == observed,
                              "recovery changed an unrelated directory")
            }
            // Keep the unlinked journal FD in descriptors until consuming close.
            // Only the expected names disappear; no directory/leaf is deleted here.
            current = current.filter { !$0.key.hasPrefix(Self.savedVersionJournal + "/") }
            current[Self.version] = restored
            directories.removeValue(forKey: Self.savedVersionJournal)
            savedVersionPending = false
            acceptedStages.insert("saved-version-rollback")
            try assertUnchanged()
        }
        func savedVersionAfterDigest() throws -> String {
            guard let bytes = changes["version"]?[Self.version] else { throw Refusal.condition("fixture: fixed version after DATA absent") }
            return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        }
        private func checkRoster() throws {
            for value in anchors { try checkDirectory(value) }
            let leafPaths = Set(current.keys)
            let expectedDirectories = Set(Self.ancestors(leafPaths))
            try Self.need(Set(directories.keys) == expectedDirectories, "unexpected registered directory")
            for path in expectedDirectories.sorted() {
                guard let directory = directories[path] else { throw Refusal.condition("fixture: directory absent") }
                let prefix = path.isEmpty ? "" : path + "/"
                var expected = Set(leafPaths.union(expectedDirectories).compactMap { item -> String? in
                    guard item.hasPrefix(prefix), item != path else { return nil }
                    let suffix = String(item.dropFirst(prefix.count))
                    return suffix.contains("/") ? nil : suffix
                })
                if path == "project" && iosUnsignedProfile && iosCompleted && iosIdentity != nil && iosDirectories.count == 4 {
                    expected.insert(".mobile-release") // Fixed completed iOS namespace; no other input-parent exception.
                }
                try Self.need(try children(directory) == expected, "unexpected owned output under " + path)
            }
            let project = directories["project"]!
            for name in Self.controls + [".git"] {
                if savedVersionPending && name == ".mobile-release-version" { continue }
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
            let androidPositive = profile == .androidSignedBuild
            let iosUnsigned = profile == .iosUnsignedArchive
            let resourceName = iosUnsigned ? "normal-ios-unsigned-v1" : androidPositive ? "normal-android-positive-v1" : projectData ? "normal-project-v1" : "normal-persistence-v1"
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
            if androidPositive {
                try Self.need(data.count == Self.androidPositiveBytes
                    && SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == Self.androidPositiveSHA256,
                    "Android exact bundled public DATA pin")
            }
            if iosUnsigned {
                try Self.need(data.count == 10237
                    && SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined()
                        == "999a48f946b2a26164d250086d5ece7588f3ff9b2b88824e596168b82faa8daf",
                    "iOS exact bundled public DATA pin")
            }
            let spec = try JSONDecoder().decode(FixtureSpec.self, from: data)
            let stagePaths: [String: Set<String>] = projectData && !androidPositive && !iosUnsigned ? [
                "config": [Self.config, "project/.gitignore"], "workflows": Set(Self.callers),
                "text": [Self.title], "version": [Self.version], "images": Set(Self.imageTargets)
            ] : [:]
            let expectedOriginals = iosUnsigned ? Self.iosUnsignedPaths : androidPositive ? Self.androidPositivePaths : projectData ? Self.originals : Self.persistenceOriginals
            try Self.need(spec.schemaVersion == 1 && Set(spec.files.keys) == expectedOriginals
                && Set(spec.stages.keys) == Set(stagePaths.keys)
                && (projectData && !androidPositive && !iosUnsigned ? spec.templateDataSHA256?.count == 64 : spec.templateDataSHA256 == nil),
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
            if iosUnsigned {
                try Self.need(originals.count == 9 && Self.ancestors(Set(originals.keys)).count == 9
                    && originals.values.reduce(0, { $0 + $1.count }) == 7264,
                    "iOS fixed public input census")
                iosUnsignedProfile = true
            }
            if androidPositive {
                originals[Self.androidVerificationPath] = try androidVerificationResource()
                try Self.need(originals.count == 17 && Self.ancestors(Set(originals.keys)).count == 17
                    && originals.values.reduce(0, { $0 + $1.count }) == 101_174,
                    "Android public input census differs")
                androidPositiveProfile = true
            }
            if profile == .releaseEvidence {
                try Self.need(originals.count == 13 && Self.releaseEvidenceDocuments.count == 3,
                              "saved-evidence original project/document census differs")
                for (path, encoded, size, digest) in Self.releaseEvidenceDocuments {
                    guard let bytes = Data(base64Encoded: encoded) else { throw Refusal.condition("fixture: fixed evidence DATA encoding") }
                    try Self.need(originals[path] == nil && bytes.count == size && size <= 4096
                        && SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() == digest,
                        "saved-evidence exact public bytes differ")
                    originals[path] = bytes
                }
                // 12 held directory originals +3 anchors, one transient reader:
                // at most16 fixture FDs; the app's original gate is separate.
                try Self.need(originals.count == 16 && Self.ancestors(Set(originals.keys)).count == 12
                    && originals.values.reduce(0, { $0 + $1.count }) == 12740,
                    "saved-evidence fixed16-leaf/12-directory DATA census differs")
            }
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
            if profile == .savedVersionRecovery {
                guard let ignore = changes["config"]?["project/.gitignore"] else { throw Refusal.condition("fixture: fixed recovery ignore DATA absent") }
                originals["project/.gitignore"] = ignore // Only before original admission; never after a snapshot.
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
            if profile == .savedVersionRecovery {
                try adoptSavedVersion(data, temporary: temporary)
                return
            }
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
            let createdRoot = try adoptDirectory(openat(temporary.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                parent: temporary.fd, name: name)
            directories[""] = createdRoot // Retain the one adopted FD even if initialization refuses.
            let initialized = try Self.initializeNewPrivateRootGroup(createdRoot.fd, parent: temporary.fd,
                                                                     name: name, created: createdRoot.facts)
            let root = Directory(fd: createdRoot.fd, parent: createdRoot.parent, name: createdRoot.name, facts: initialized)
            directories[""] = root // Replace only admitted facts; never adopt or close the FD twice.
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
                let saved = try androidPositive && path == Self.androidVerificationPath ? readAndroidVerificationOriginal() : read(path)
                try Self.need(saved.bytes == bytes && saved.facts.mode & 0o7777 == mode, "new fixture readback failed")
                current[path] = saved
            }
            try checkRoster()
            if profile == .projectFields {
                try Self.need(current.count == 22 && directories.count == 143 && anchors.count == 3
                    && descriptors.count == 146, "created Android source fixture census differs")
            }
            if profile == .releaseEvidence {
                try Self.need(current.count == 16 && directories.count == 12 && anchors.count == 3
                    && descriptors.count == 15, "created saved-evidence original census differs")
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
        func androidSavedDigest(_ path: String) throws -> String {
            try Self.need(androidPositiveProfile && acceptedStages == ["android-public-certificate"]
                && [Self.config, Self.version].contains(path), "Android saved public digest role")
            guard let value = current[path] else { throw Refusal.condition("Android saved public original absent") }
            return SHA256.hash(data: value.bytes).map { String(format: "%02x", $0) }.joined()
        }
        func assertUnchanged() throws {
            for path in current.keys.sorted() {
                let old = current[path]!
                let observed = try androidPositiveProfile && path == Self.androidVerificationPath ? readAndroidVerificationOriginal() : read(path)
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
                let observed = try androidPositiveProfile && path == Self.androidVerificationPath ? readAndroidVerificationOriginal() : read(path)
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
            let missingAndroidClosure = androidOutput != nil && !androidClosing
            let missingIOSClosure = iosIdentity != nil && !iosClosing
            // Consume each original exactly once, including after partial setup.
            // Never retry close or search/reopen a replacement descriptor.
            while let fd = descriptors.popLast() {
                if Darwin.close(fd) != 0 { closeErrors.append("directory-close") }
            }
            directories.removeAll(); anchors.removeAll()
            applicationSupport = nil; applicationDirectory = nil; vaultDirectory = nil
            try Self.need(!missingIOSClosure, "iOS final output observation was not joined before close")
            try Self.need(!missingAndroidClosure, "Android final output observation was not joined before close")
            try Self.need(closeErrors.isEmpty, "original close errors: " + closeErrors.joined(separator: ","))
        }
    }


    // Read only the ordinary parsed-current Build details within the caller's
    // exact review or original-status container, never the three panels globally.
    @MainActor private func androidCurrentBuildIdentity(_ container: XCUIElement) throws -> LocalFixture.AndroidBuildIdentity {
        let details = try unique(container.descendants(matching: .group).matching(identifier: "Build details"),
                                 "current Android Build details missing or repeated")
        var values: [String] = []
        for prefix in ["Build operation ID: ", "Build owner generation: "] {
            let field = try unique(details.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)),
                                   "current Android build identity field missing or repeated")
            let label = field.label
            try require(field.isHittable && label.hasPrefix(prefix), "current Android build identity is not visible")
            let value = String(label.dropFirst(prefix.count))
            try require(value.range(of: #"^[0-9a-f]{32}$"#, options: .regularExpression) != nil,
                        "current Android build identity shape differs")
            values.append(value)
        }
        return try LocalFixture.AndroidBuildIdentity(operationID: values[0], ownerGeneration: values[1])
    }

    // Legacy fixed selector, now Android+iOS filesystem DATA only. Neither an
    // application case nor an archive/signing observation; same original 30s.
    func testPositiveAndroidOutputCustodyData() throws {
        try LocalFixture.exerciseAndroidOutputCustodyData()
    }

    @MainActor private var ownedFixture: LocalFixture?
    @MainActor private var ownedAndroidInputs: LocalFixture.AndroidInputs?
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
                                       failures: [String] = [], line: UInt = #line) throws -> XCUIElement {
        let first = query.element(boundBy: 0)
        let failed = root.staticTexts.matching(NSPredicate(format: "label IN %@", failures))
        let targets: NSDictionary = ["ready": first, "failed": failed.element(boundBy: 0)]
        let ready = "ready.exists == true" + (enabled ? " AND ready.enabled == true" : "")
        let predicate = NSPredicate(format: "(" + ready + ") OR failed.exists == true")
        let expected = XCTNSPredicateExpectation(predicate: predicate, object: targets)
        let result = XCTWaiter.wait(for: [expected], timeout: try remaining(timeout))
        if failed.count > 0 {
            diagnostic(root)
            if engineeringRequireDiagnosticActive {
                try require(false, "terminal UI refusal in " + journeyStage, line: line)
            }
            throw Refusal.condition("terminal UI refusal in " + journeyStage)
        }
        if result != .completed || query.count != 1 {
            diagnostic(root)
            if engineeringRequireDiagnosticActive {
                try require(false, "missing or ambiguous expected control in " + journeyStage, line: line)
            }
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
    // One real interrupted core process, then a fresh ordinary app's registered
    // project/recovery owner. This is not a crash during a GUI-originated Save.
    @MainActor func testSyntheticProjectSavedVersionRecovery() throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300)
        let fixture = LocalFixture()
        ownedFixture = fixture
        try stage("saved-version-fixture") { try fixture.prepare(.savedVersionRecovery) }
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("saved-version-launch") { launched = try launchForJourney() }
        guard let (app, window, renderer) = launched else { throw Refusal.condition("ordinary recovery launch returned no original") }
        try stage("saved-version-project-open") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(sheet, path: fixture.projectPath)
            try nativeOpen(sheet)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "recovery selected project differs")
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)
            try fixture.assertSavedVersionPending()
        }
        try press(renderer, "Dashboard", renderer: renderer)
        let editor = try waitElement(named(renderer, "Edit or create saved version values"), in: renderer)
        // No normal Open, placeholder baseline, or submitted draft is needed.
        let panel = try waitElement(named(editor, "Saved-version recovery inspection"), in: renderer)
        func inspect() throws {
            try press(panel, "Inspect recovery", renderer: renderer)
            _ = try waitElement(panel.buttons.matching(identifier: "Review recovery confirmation…"), in: panel,
                                enabled: true, timeout: 48)
            _ = try unique(panel.staticTexts.matching(NSPredicate(format: "title == %@", "Roll back the interrupted save")), "exact rollback action absent")
            try inventory(panel, caption: "Inspected journal files — not your current draft", paths: ["release/version.properties"])
            _ = try unique(panel.staticTexts.matching(identifier: "restore original"), "version recovery effect differs")
            for digest in [try fixture.digest(LocalFixture.version), try fixture.savedVersionAfterDigest()] {
                _ = try unique(panel.staticTexts.matching(identifier: "SHA256 " + digest), "recovery review digest differs")
            }
            let beforeBytes = try fixture.text(LocalFixture.version).utf8.count
            let afterBytes = try fixture.text(LocalFixture.version, stage: "version").utf8.count
            for count in Set([beforeBytes, afterBytes]) {
                try require(panel.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "\(count) bytes · mode 0600")).count >= 1,
                            "recovery byte/mode facts unavailable")
            }
            _ = try unique(panel.staticTexts.matching(identifier:
                "Private cleanup is limited to 5 inspected owned files and 0 directories. No other domain, current draft, Store state or build-input recovery is included."),
                "recovery private cleanup scope differs")
            try fixture.assertSavedVersionPending()
        }
        try stage("saved-version-inspect-close") {
            try inspect()
            try press(panel, "Close inspection, keep drafts", renderer: renderer)
            _ = try waitElement(panel.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "Native: settled; reason: discarded.")),
                                in: panel, timeout: 48)
            _ = try waitElement(panel.buttons.matching(identifier: "Inspect recovery"), in: panel, enabled: true, timeout: 48)
            try require(panel.buttons.matching(identifier: "Review recovery confirmation…").count == 0,
                        "closed original recovery review still permits Apply")
            try fixture.assertSavedVersionPending()
        }
        try stage("saved-version-reinspect-confirm") {
            try inspect()
            try press(panel, "Review recovery confirmation…", renderer: renderer)
            let dialog = try waitElement(renderer.dialogs.matching(identifier: "Roll back the interrupted save?"), in: renderer)
            _ = try unique(dialog.staticTexts.matching(identifier: fixture.savedVersionTransaction), "confirmation journal is not the original")
            let apply = try unique(dialog.buttons.matching(identifier: "Confirm recovery action"), "recovery Apply is ambiguous")
            try require(!apply.isEnabled, "recovery Apply began enabled without consent")
            let checkbox = try waitElement(dialog.checkBoxes.matching(NSPredicate(format: "title == %@",
                "I reviewed the action, exact file effects, both byte/digest/mode summaries and private cleanup scope.")), in: dialog, enabled: true)
            try require((checkbox.value as? String) == "0" || (checkbox.value as? NSNumber)?.intValue == 0, "recovery consent started checked")
            try reveal(checkbox, in: renderer); checkbox.click()
            try require(!apply.isEnabled, "recovery typed confirmation was not required")
            try replace(field(dialog, "Type RECOVER to confirm this one original plan"), with: "RECOVER", renderer: renderer)
            try fixture.assertSavedVersionPending()
            try press(dialog, "Confirm recovery action", renderer: renderer) // Exactly one Apply.
            try waitGone(dialog)
            _ = try waitElement(panel.staticTexts.matching(identifier: "Original recovery action completed; current draft kept."),
                                in: panel, timeout: 48)
            _ = try waitElement(panel.staticTexts.matching(identifier:
                "Original effect: rolled_back; journal: clean; core resources: settled; core reason: none. Native: settled; reason: none."),
                in: panel, timeout: 48)
            try fixture.acceptSavedVersionRollback()
        }
        try stage("saved-version-reload") {
            let saved = try waitElement(named(renderer, "Saved version and build"), in: renderer)
            try press(saved, "Read saved version", renderer: renderer)
            _ = try waitElement(saved.staticTexts.matching(identifier: "Observed from saved version file"), in: saved)
            _ = try unique(saved.staticTexts.matching(identifier: "1.2.3"), "fresh saved version is not the restored original")
            _ = try unique(saved.staticTexts.matching(identifier: "Build number 7"), "fresh saved build is not the restored original")
            try fixture.assertUnchanged()
        }
        try stage("saved-version-readback-and-quit") {
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "normal affirmative Quit unavailable")
            try completeNormalQuit(app)
            try fixture.assertUnchanged()
            try fixture.closeOriginals()
            ownedFixture = nil
        }
        try acceptFinalScenario()
        print("MRK_MACOS_NORMAL_SAVED_VERSION_RECOVERY_UI=original-core-interrupt86-fresh-ui-inspect-close-reinspect-confirm-rollback-reload;interruptedGuiSave=not-observed;cleanExitStatus=unavailable;allWorkerFinality=unavailable")
    }

    @MainActor func testSyntheticProjectSavedReleaseEvidence() throws {
        continueAfterFailure = false
        executionTimeAllowance = 300
        try beginCase(seconds: 300)
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        try stage("evidence-launch") { launched = try launchForJourney() }
        guard let (app, window, renderer) = launched else { throw Refusal.condition("ordinary launch returned no original") }
        let fixture = LocalFixture()
        ownedFixture = fixture
        try stage("evidence-fixture") { try fixture.prepare(.releaseEvidence) }
        let guidance = "Only candidate evidence was supplied. Later stages and recovery remain undetermined; these saved documents do not approve another operation."
        let warning = "Saved documents only, not live Store status or retry approval."
        let failures = ["No current evidence result was accepted", "Some documents are missing", "A document needs attention", "The documents do not agree",
                        "Evidence observation or cleanup is unconfirmed. Preserve the original folder; do not treat it as a successful observation."]
        @MainActor func currentDocuments() throws {
            _ = try waitElement(renderer.staticTexts.matching(identifier: "Documents agree"), in: renderer, failures: failures)
            _ = try unique(renderer.staticTexts.matching(identifier: "Documents only"), "documents-only label missing or ambiguous")
            _ = try unique(renderer.staticTexts.matching(identifier: "com.example.reader"), "declared candidate identity differs")
            _ = try unique(renderer.staticTexts.matching(identifier: "evidence · Candidate"), "selected evidence folder and stage differ")
            _ = try unique(renderer.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", guidance)), "candidate-only guidance differs")
            _ = try unique(renderer.staticTexts.matching(identifier: warning), "saved documents warning missing")
            try require(renderer.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "unchanged by evidence selection")).count == 1,
                        "source-project separation was not displayed")
        }
        @MainActor func staleDocuments() throws {
            _ = try waitElement(controls(renderer, [.disclosureTriangle, .button], label: "Previous observation · stale · evidence", prefix: true), in: renderer)
            try require(renderer.staticTexts.matching(identifier: "Documents agree").count == 0,
                        "a previous observation is still presented as a current document result")
        }
        @MainActor func releaseSeparation() throws {
            for label in ["Candidate evidence producer run ID", "Original artifact source commit", "Original marketing version", "Original build number"] {
                let input = try field(renderer, label)
                try require(input.value as? String == "", "saved evidence populated a protected-release input")
            }
            let prepare = try unique(renderer.buttons.matching(identifier: "Prepare release review · read GitHub only"), "release Prepare missing or ambiguous")
            try require(!prepare.isEnabled, "saved evidence enabled disconnected release preparation")
            try require(renderer.buttons.matching(identifier: "Dispatch this protected release request once").count == 0
                && named(renderer, "Exact protected release review").count == 0,
                "saved evidence acquired a prepared review or dispatch authority")
        }
        try stage("evidence-project-open") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(sheet, path: fixture.projectPath); try nativeOpen(sheet)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")), in: renderer,
                                failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "source project path differs")
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.fixture.app"), in: renderer)
            try fixture.assertUnchanged()
        }
        try stage("evidence-real-picker") {
            try press(renderer, "Artifacts", renderer: renderer)
            _ = try waitElement(renderer.staticTexts.matching(identifier: "No current document observation"), in: renderer)
            let selected = try waitElement(controls(renderer, [.popUpButton, .comboBox], label: "Evidence stage", prefix: true), in: renderer)
            try require(selected.value as? String == "Candidate", "initial evidence stage is not candidate")
            try press(renderer, "Choose evidence folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a release evidence folder")
            try goToFolder(sheet, path: fixture.evidencePath); try nativeOpen(sheet)
            _ = try waitElement(renderer.buttons.matching(identifier: "Inspect documents"), in: renderer, enabled: true, failures: failures)
            try require(renderer.staticTexts.matching(identifier: "Documents agree").count == 0,
                        "choosing a folder synthesized an observation")
            try fixture.assertUnchanged()
        }
        try stage("evidence-original-observation") {
            try press(renderer, "Inspect documents", renderer: renderer, failures: failures) // Exactly one observation request.
            try currentDocuments()
            try expand(renderer, prefix: "Document status and technical details", renderer: renderer)
            _ = try waitElement(renderer.staticTexts.matching(identifier: "No artifact bytes, signing, GitHub authenticity, Store state, release readiness or recovery safety are established here. All six assurance flags remain false."), in: renderer)
            for path in ["candidate-receipt.json", "candidate-manifest.json", "operation/candidate-operation-intent.json"] {
                try require(renderer.staticTexts.matching(identifier: path).count >= 1, "an expected saved document is absent from the observation")
            }
            try fixture.assertUnchanged()
        }
        try stage("evidence-shared-navigation") {
            try press(renderer, "Releases", renderer: renderer); try currentDocuments()
            try select(renderer, label: "Release step", value: "External testing · reuse candidate", renderer: renderer)
            try select(renderer, label: "Release platform", value: "Android · Google Play", renderer: renderer)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "Promote the original candidate to the configured external testing track without rebuilding it.")), in: renderer)
            try releaseSeparation() // No Prepare, consent or Dispatch click.
            try press(renderer, "Artifacts", renderer: renderer); try currentDocuments()
            try press(renderer, "Recovery", renderer: renderer)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", guidance)), in: renderer)
            _ = try unique(renderer.staticTexts.matching(identifier: warning), "shared recovery warning differs")
            try require(renderer.staticTexts.matching(identifier: "No current saved-document guidance. Project recovery remains unassessed.").count == 0,
                        "navigation discarded the actual shared candidate observation")
            try fixture.assertUnchanged()
        }
        try stage("evidence-stage-and-cancel") {
            try press(renderer, "Releases", renderer: renderer)
            try select(renderer, label: "Evidence stage", value: "External testing", renderer: renderer)
            try currentDocuments() // Stage choice alone does not stale the existing result.
            let inspect = try unique(renderer.buttons.matching(identifier: "Inspect documents"), "Inspect control missing")
            try require(!inspect.isEnabled, "a new evidence stage reused the prior selection")
            try press(renderer, "Choose evidence folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a release evidence folder")
            try click(sheet.buttons.matching(identifier: "Cancel"), "replacement evidence Cancel unavailable")
            try waitGone(sheet)
            _ = try waitElement(renderer.staticTexts.matching(identifier: "Original operation cancelled and settled. No new result was accepted."), in: renderer, failures: failures)
            try staleDocuments(); try releaseSeparation()
            try press(renderer, "Artifacts", renderer: renderer); try staleDocuments()
            try press(renderer, "Recovery", renderer: renderer)
            _ = try waitElement(renderer.staticTexts.matching(identifier: "No current saved-document guidance. Project recovery remains unassessed."), in: renderer)
            _ = try waitElement(controls(renderer, [.disclosureTriangle, .button], label: "Previous guidance · stale · evidence", prefix: true), in: renderer)
            try fixture.assertUnchanged()
        }
        try stage("evidence-readback-and-quit") {
            try press(renderer, "Dashboard", renderer: renderer)
            _ = try waitElement(renderer.staticTexts.matching(identifier: fixture.projectPath), in: renderer)
            try fixture.assertUnchanged()
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "saved-evidence normal Quit unavailable")
            try completeNormalQuit(app)
            try fixture.assertUnchanged()
            try fixture.closeOriginals()
            ownedFixture = nil
        }
        try acceptFinalScenario()
        print("MRK_MACOS_NORMAL_RELEASE_EVIDENCE_UI=ordinary-picker-candidate-documents-only-shared-guidance-stage-retained-replacement-cancel-stale-release-inputs-empty-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable;remoteRelease=not-attempted")
    }

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

    // All strings read here stay private. Only the closed public marker below is
    // eligible for the parent projection; never print an accessibility dump.
    @MainActor private func androidPublicText(_ root: XCUIElement) throws -> String {
        let query = root.staticTexts
        try require(query.count <= 256, "Android fixed panel text count")
        var value = ""
        for index in 0..<query.count {
            _ = try remaining(5)
            let text = query.element(boundBy: index).label
            try require(text.utf8.count <= 4096 && value.utf8.count + text.utf8.count + 1 <= 32768,
                        "Android fixed panel text bound")
            value += text + "\n"
        }
        return value
    }
    private static func androidMatch(_ pattern: String, in text: String) throws -> String {
        let expression = try NSRegularExpression(pattern: pattern)
        let rows = expression.matches(in: text, range: NSRange(text.startIndex..., in: text))
        guard rows.count == 1, rows[0].numberOfRanges == 2,
              let range = Range(rows[0].range(at: 1), in: text) else {
            throw Refusal.condition("Android fixed public fact absent or ambiguous")
        }
        return String(text[range])
    }
    @MainActor private func androidResult(_ result: XCUIElement, identity: LocalFixture.AndroidBuildIdentity,
                                         certificate: String) throws -> (Int, String) {
        try require(try androidCurrentBuildIdentity(result) == identity, "Android current result identity differs")
        let text = try androidPublicText(result)
        for expected in ["This build only", "Signed locally and verified with the selected upload key.",
            "Known Gradle exit: 0. Structure: passed; native manifest: passed; application version: native-checked.",
            "matches saved upload certificate", certificate, "app-release.aab · redacted local observation"] {
            try require(text.contains(expected), "Android native signed result fact missing")
        }
        try require(!text.contains("Historical / retained context"), "Android historical result refused")
        // Exactly one published AAB card. Saved-certificate text is deliberately
        // NOT the line-start SHA-256 field of that artifact card.
        let bytes = try Self.androidMatch(#"(?m)^([1-9][0-9]{0,8}) observed bytes · ABIs:"#, in: text)
        let hash = try Self.androidMatch(#"(?m)^SHA-256:[ \n]*([0-9a-f]{64})[ \n]*$"#, in: text)
        guard let count = Int(bytes), count <= 64 * 1024 * 1024 else {
            throw Refusal.condition("Android public artifact byte bound")
        }
        return (count, hash)
    }

    @MainActor private func iosCurrentArchiveIdentity(_ container: XCUIElement) throws -> LocalFixture.IOSArchiveIdentity {
        let details = try unique(container.descendants(matching: .group).matching(identifier: "Archive details"),
                                 "current unsigned Archive details missing or repeated")
        var values: [String] = []
        for prefix in ["Archive operation ID: ", "Archive owner generation: "] {
            let field = try unique(details.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)),
                                   "current unsigned archive identity absent or ambiguous")
            let text = field.label
            try require(field.isHittable && text.hasPrefix(prefix), "current unsigned archive identity not visible")
            values.append(String(text.dropFirst(prefix.count)))
        }
        return try LocalFixture.IOSArchiveIdentity(operationID: values[0], ownerGeneration: values[1])
    }
    @MainActor private func iosPublicText(_ container: XCUIElement) throws -> String {
        let query = container.staticTexts
        try require(query.count <= 256, "iOS fixed panel text count")
        var text = ""
        for index in 0..<query.count {
            _ = try remaining(5)
            let value = query.element(boundBy: index).label
            try require(value.utf8.count <= 4096 && text.utf8.count + value.utf8.count + 1 <= 32768,
                        "iOS fixed panel text bound")
            text += value + "\n"
        }
        return text.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
    }
    @MainActor private func iosResult(_ result: XCUIElement, identity: LocalFixture.IOSArchiveIdentity) throws -> (Int, Int64) {
        try require(try iosCurrentArchiveIdentity(result) == identity, "iOS current complete identity differs")
        let text = try iosPublicText(result)
        for required in ["This local artifact only", "Archive created and structurally checked — not a signed release.",
            "Archive bundle identity and saved version/build.", "Archive symbols under the saved symbols policy.",
            ".mobile-release/desktop-ios-archive/" + identity.operationID + "/archive.xcarchive"] {
            try require(text.contains(required), "iOS current unsigned result fact missing")
        }
        try require(!text.contains("Historical / retained context"), "iOS historical result refused")
        let expression = try NSRegularExpression(pattern: #"Saved version 1\.2\.3 · build 7\. ([1-9][0-9]{0,5}) observed entries · ([1-9][0-9]{0,9}) observed bytes\."#)
        let rows = expression.matches(in: text, range: NSRange(text.startIndex..., in: text))
        guard rows.count == 1, let entryRange = Range(rows[0].range(at: 1), in: text),
              let byteRange = Range(rows[0].range(at: 2), in: text), let entries = Int(text[entryRange]),
              let bytes = Int64(text[byteRange]), entries <= 100_000, bytes <= 8 * 1024 * 1024 * 1024 else {
            throw Refusal.condition("iOS typed original result counts absent or outside bounds")
        }
        return (entries, bytes) // Displayed original result, NOT a new archive census.
    }
    @MainActor private func settleFailedIOSArchive(_ app: XCUIApplication, window: XCUIElement,
                                                   panel: XCUIElement, identity: LocalFixture.IOSArchiveIdentity) throws {
        guard let clock = caseClock, clock.firstFailure != nil, let owner = originalLaunch else {
            throw Refusal.condition("iOS failure settlement requires the failed original")
        }
        // Leave ten seconds of the SAME 900s end for the existing original's
        // teardown/gate closes. No renewed work, new owner or successful outcome.
        let end = min(clock.deadline - 10, try clock.end(within: 140, cleanup: true))
        func check() throws {
            _ = try clock.remaining(1, before: end, cleanup: true)
            try owner.healthy(cleanup: true)
        }
        func need(_ value: Bool) throws {
            try check()
            guard value else { throw Refusal.condition("iOS original failure settlement unavailable") }
        }
        func only(_ query: XCUIElementQuery) throws -> XCUIElement {
            try need(query.count == 1)
            return query.element(boundBy: 0)
        }
        func click(_ query: XCUIElementQuery) throws {
            let item = try only(query)
            try need(item.isEnabled && item.isHittable)
            item.click()
        }
        var cancelRequested = false, statusRequested = false
        while true {
            try check()
            let status = try only(panel.descendants(matching: .any).matching(identifier: "Original iOS archive status"))
            let details = try only(status.descendants(matching: .group).matching(identifier: "Archive details"))
            for (prefix, expected) in [("Archive operation ID: ", identity.operationID), ("Archive owner generation: ", identity.ownerGeneration)] {
                let field = try only(details.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)))
                try need(field.label == prefix + expected)
            }
            if status.staticTexts.matching(identifier: "iOS request finished").count == 1 { break }
            if !cancelRequested {
                let cancel = panel.buttons.matching(identifier: "Cancel this iOS archive")
                try need(cancel.count == 1)
                cancelRequested = true // Consume before any click/acknowledgement can fail.
                try click(cancel)
            }
            if !statusRequested {
                let read = panel.buttons.matching(identifier: "Check archive status")
                if read.count == 1 && read.element(boundBy: 0).isEnabled && read.element(boundBy: 0).isHittable {
                    statusRequested = true
                    try click(read)
                }
            }
            try clock.progress(until: end, cleanup: true)
        }
        // Same fixed native Quit UI, scoped to the retained application's menu.
        // This is failure settlement only; normalQuitObserved stays false.
        try need(window.sheets.count == 0)
        let menu = try only(app.menuBars)
        try click(menu.menuBarItems.matching(identifier: "Mobile Release Kit"))
        try click(menu.menuItems.matching(identifier: "Quit"))
        while window.sheets.count == 0 { try clock.progress(until: end, cleanup: true) }
        let sheet = try only(window.sheets)
        try need(sheet.staticTexts.matching(identifier: "Quit and discard unsaved drafts?").count == 1
            && sheet.buttons.count == 2 && sheet.buttons.matching(identifier: "Cancel").count == 1)
        try click(sheet.buttons.matching(identifier: "Quit"))
        try need(app.wait(for: .notRunning, timeout: try clock.remaining(10, before: end, cleanup: true)))
    }

    @MainActor func testSyntheticProjectUnsignedIOSArchive() throws {
        continueAfterFailure = false
        executionTimeAllowance = 900
        try beginCase(seconds: 900, iosUnsigned: true)
        guard let clock = caseClock else { throw Refusal.condition("iOS original clock absent") }
        let successCutoff = clock.deadline - 150
        journeyDeadline = successCutoff
        let fixture = LocalFixture()
        ownedFixture = fixture
        var launched: (XCUIApplication, XCUIElement, XCUIElement)?
        var selected: XCUIElement?
        var identity: LocalFixture.IOSArchiveIdentity?
        var observed: (Int, Int64)?
        var successBeforeCutoff = false
        do {
            try stage("ios-unsigned-fixture") { try fixture.prepare(.iosUnsignedArchive) }
            try stage("ios-unsigned-launch") { launched = try launchForJourney() }
            guard let (app, window, renderer) = launched else { throw Refusal.condition("iOS ordinary launch absent") }
            try stage("ios-unsigned-project") {
                try press(renderer, "Open project folder", renderer: renderer)
                let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
                try goToFolder(sheet, path: fixture.projectPath); try nativeOpen(sheet)
                _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")),
                                    in: renderer, failures: ["Static observation unavailable", "Only a partial static observation is available"])
                _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "iOS selected fixture differs")
                _ = try waitElement(renderer.staticTexts.matching(identifier: "org.example.mrk.observed"), in: renderer)
                try fixture.assertUnchanged()
            }
            let failures = ["No new iOS archive outcome was confirmed", "Cleanup needs attention"]
            try stage("ios-unsigned-review") {
                try press(renderer, "Releases", renderer: renderer)
                let panel = try waitElement(named(renderer, "Review the current saved inputs")
                    .containing(.button, identifier: "Review saved iOS inputs"), in: renderer)
                selected = panel
                try require(named(panel, "Completed local unsigned iOS archive observation").count == 0
                    && named(panel, "Original iOS archive status").count == 0, "iOS prior operation cannot supply this journey")
                try press(panel, "Refresh saved configuration", renderer: renderer, failures: failures)
                try press(panel, "Read saved version", renderer: renderer, failures: failures)
                try press(panel, "Review saved iOS inputs", renderer: renderer, failures: failures)
                let review = try waitElement(named(panel, "Confirm this saved unsigned iOS archive intent"), in: panel, failures: failures)
                let text = try iosPublicText(review)
                for expected in ["ios/MRKObserved.xcodeproj", "MRKObserved", "Release", "org.example.mrk.observed", "Saved preparation is not configured."] {
                    try require(text.contains(expected), "iOS saved unsigned selection differs")
                }
                let pair = try iosCurrentArchiveIdentity(review)
                identity = pair
                try fixture.beginIOSArchiveObservation(pair) { _ = try self.remaining(5) }
                let consent = try waitElement(controls(review, [.checkBox], label:
                    "I trust this project and authorize one unsigned archive of these saved inputs.", prefix: true), in: review, enabled: true)
                try reveal(consent, in: renderer)
                try require(consent.value as? String == "0", "iOS trust consent must begin unchecked")
                consent.click()
                try require(consent.value as? String == "1", "iOS explicit trust consent not observed")
                try require(try iosCurrentArchiveIdentity(review) == pair, "iOS review identity changed before Start")
                try fixture.confirmIOSArchiveStart(pair) { _ = try self.remaining(5) }
                try press(review, "Create unsigned archive", renderer: renderer, failures: failures) // Exactly ONE Start.
            }
            guard let panel = selected, let pair = identity else { throw Refusal.condition("iOS selected original absent") }
            try stage("ios-unsigned-original-result") {
                let result = try waitElement(named(panel, "Completed local unsigned iOS archive observation"),
                    in: panel, timeout: 750, failures: failures)
                try reveal(result, in: renderer)
                observed = try iosResult(result, identity: pair)
                let status = try unique(named(panel, "Original iOS archive status"), "iOS current terminal status absent")
                try require(try iosCurrentArchiveIdentity(status) == pair, "iOS terminal status identity differs")
                let text = try iosPublicText(status)
                for required in ["iOS request finished", "Xcode version: known exit 0.", "iOS SDK selection: known exit 0.",
                    "Saved preparation: not configured.", "Archive: known exit 0.",
                    "Inspection snapshot: removed. Task work: removed. Archive output: retained-local-result."] {
                    try require(text.contains(required), "iOS original command/finality fact missing")
                }
                try require(!text.contains("This is retained original-operation data"), "iOS historical original status refused")
                try fixture.finishIOSArchiveObservation(pair) { _ = try self.remaining(5) }
                _ = try clock.remaining(1, before: successCutoff)
                successBeforeCutoff = true // Only here; neither Quit nor cleanup can create success.
            }
            journeyDeadline = clock.deadline // Remaining original reserve, never a new deadline.
            try stage("ios-unsigned-close") {
                try require(successBeforeCutoff, "iOS successful observation missed original cutoff")
                try fixture.assertIOSArchiveClosure(pair) { _ = try self.remaining(5) }
                let sheet = try quitSheet(app, window)
                try click(sheet.buttons.matching(identifier: "Quit"), "iOS ordinary Quit unavailable")
                try completeNormalQuit(app)
                try fixture.closeIOSArchiveOriginals(pair) { _ = try self.remaining(5) }
                ownedFixture = nil
            }
            guard let observed else { throw Refusal.condition("iOS typed original result missing") }
            try require(successBeforeCutoff, "iOS original cutoff acceptance missing")
            try acceptFinalScenario()
            let facts: [String: Any] = ["schemaVersion": 1, "scope": "one-ordinary-local-unsigned-ios-archive",
                "sourceCommit": ProcessInfo.processInfo.environment["MRK_NORMAL_UI_HARNESS_SOURCE"] ?? "",
                "operationId": pair.operationID, "ownerGeneration": pair.ownerGeneration,
                "savedVersion": "1.2.3", "savedBuild": 7, "originalEntries": observed.0, "originalBytes": observed.1,
                "inputFiles": 9, "inputBytes": 7264, "topLevelDirectories": 4,
                "archiveDescendantsObserved": false, "nativeResultDisplayed": true, "outputPostMatched": true,
                "originalsClosed": true, "normalQuitObserved": true, "successBeforeCutoff": true,
                "signed": false, "ipaExported": false, "releaseQualified": false, "parentReturncodeRequired": 0]
            let raw = try JSONSerialization.data(withJSONObject: facts, options: [.sortedKeys, .withoutEscapingSlashes])
            try require(raw.count <= 16 * 1024, "iOS closed public result bound")
            _ = try remaining(1)
            print("MRK_MACOS_IOS_UNSIGNED_ARCHIVE_UI=" + String(decoding: raw, as: UTF8.self))
        } catch {
            let primary = error
            _ = clock.fail("unsigned iOS observation failed") // Never clear/replace a prior original failure.
            if let (app, window, _) = launched, let panel = selected, let pair = identity, !normalQuitObserved {
                do { try settleFailedIOSArchive(app, window: window, panel: panel, identity: pair) }
                catch { /* Same-original failure/unknown retained; teardown still consumes its originals. */ }
            }
            throw primary
        }
    }

    @MainActor func testSyntheticProjectAndroidSignedBuild() throws {
        continueAfterFailure = false
        executionTimeAllowance = 900
        try beginCase(seconds: 900, androidPositive: true)
        let fixture = LocalFixture()
        ownedFixture = fixture
        var inputs: LocalFixture.AndroidInputs?
        var certificate = ""
        try stage("android-private-admission") {
            let admitted = try LocalFixture.AndroidInputs.admit { _ = try self.remaining(5) }
            ownedAndroidInputs = admitted; inputs = admitted
            certificate = admitted.publicCertificate
            try fixture.prepare(.androidSignedBuild)
            try fixture.prepareAndroidCertificate(certificate)
        }
        guard let initialInputs = inputs else { throw Refusal.condition("Android private input admission absent") }
        let (app, window, renderer) = try launchForJourney()
        try stage("android-public-project-and-certificate") {
            try press(renderer, "Open project folder", renderer: renderer)
            let sheet = try nativeSheet(window, title: "Choose a mobile project folder")
            try goToFolder(sheet, path: fixture.projectPath); try nativeOpen(sheet)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Let’s get project ready.")),
                                in: renderer, failures: ["Static observation unavailable", "Only a partial static observation is available"])
            _ = try unique(renderer.staticTexts.matching(identifier: fixture.projectPath), "Android project selection differs")
            _ = try waitElement(renderer.staticTexts.matching(identifier: "org.example.saved"), in: renderer)
            try press(renderer, "Project settings", renderer: renderer)
            let settings = try waitElement(named(renderer, "Settings section"), in: renderer)
            try press(settings, "Android", renderer: renderer)
            try replace(field(renderer, "Android upload certificate"), with: certificate, renderer: renderer)
            try press(renderer, "Validate only", renderer: renderer)
            _ = try waitElement(renderer.staticTexts.matching(NSPredicate(format: "title == %@", "Format validation complete")),
                                in: renderer, failures: Self.configurationFailures)
            try press(renderer, "Prepare save review", renderer: renderer, failures: Self.configurationFailures)
            let review = try waitElement(named(renderer, "Native configuration save"), in: renderer)
            try inventory(review, caption: "Exact native destination inventory", paths: ["release/mobile-release.json", ".gitignore"])
            try fixture.assertUnchanged()
            try press(review, "Apply reviewed save", renderer: renderer, failures: Self.configurationFailures, timeout: 48)
            try confirmedDialog(renderer, title: "Apply this configuration save?", action: "Apply reviewed save",
                                checkbox: "I reviewed this exact inventory and understand that cancellation may be too late after Apply.")
            _ = try waitElement(review.staticTexts.matching(NSPredicate(format: "title == %@", "Submitted configuration saved")),
                                in: review, timeout: 48, failures: Self.configurationFailures)
            try fixture.accept("android-public-certificate")
            try initialInputs.post { _ = try self.remaining(5) }
        }
        try stage("android-saved-input-read") {
            try press(renderer, "Releases", renderer: renderer)
            try press(renderer, "Refresh saved configuration", renderer: renderer, timeout: 48)
            try press(renderer, "Read saved version", renderer: renderer, timeout: 48)
            _ = try waitElement(renderer.buttons.matching(identifier: "Review saved inputs"), in: renderer, timeout: 48)
            try fixture.assertUnchanged()
        }
        try stage("android-source-inspection-without-license-acceptance") {
            let roles = [("jdk", "Java development kit (JDK)", "Choose an installed Java 17 JDK folder", "temurin-17.jdk"),
                         ("sdk", "Android SDK", "Choose the Android SDK folder", "sdk"),
                         ("gradle", "Gradle distribution", "Choose an extracted Gradle distribution folder", "gradle")]
            for (role, label, title, leaf) in roles {
                let group = try waitElement(controls(renderer, [.group], label: label + " source folder"), in: renderer)
                try press(group, "Browse for folder", renderer: renderer, timeout: 48)
                let sheet = try nativeSheet(window, title: title)
                try goToFolder(sheet, path: initialInputs.sourcePath(role)); try nativeOpen(sheet)
                _ = try waitElement(group.staticTexts.matching(NSPredicate(format: "label == %@ OR label CONTAINS %@",
                    leaf, "Selected folder: " + leaf + " · folder selection only.")), in: group, timeout: 48)
                _ = try waitElement(group.buttons.matching(identifier: "Choose a different folder"), in: group, enabled: true, timeout: 48)
                try initialInputs.post { _ = try self.remaining(5) }
            }
            try press(renderer, "Inspect selected sources", renderer: renderer, timeout: 48)
            let review = try waitElement(controls(renderer, [.group], label: "Confirm this exact protected-copy review"),
                in: renderer, timeout: 120, failures: ["Inspection or registration refused", "Original cleanup is unconfirmed"])
            let text = try androidPublicText(review)
            for fact in ["complete compatible role observation", try fixture.androidSavedDigest(LocalFixture.config),
                         try fixture.androidSavedDigest(LocalFixture.version)] {
                try require(text.contains(fact), "Android source review saved binding differs")
            }
            let license = try unique(review.checkBoxes.matching(NSPredicate(format: "label BEGINSWITH %@",
                "I acknowledge the applicable vendor licenses")), "Android separate vendor consent absent")
            try require((license.value as? String) == "0" || (license.value as? NSNumber)?.intValue == 0,
                        "Android vendor consent must remain unchecked")
            let register = try unique(review.buttons.matching(identifier: "Register protected tool copy"),
                                      "Android separate protected registration unavailable")
            try require(!register.isEnabled, "Android protected registration enabled without legal authorization")
            // Deliberately NO vendor acknowledgement, registration or system approval.
            try press(renderer, "Discard this source review", renderer: renderer, timeout: 48)
            try waitGone(review)
            _ = try waitElement(renderer.buttons.matching(identifier: "Inspect selected sources"), in: renderer, enabled: true, timeout: 48)
            try fixture.assertUnchanged(); try initialInputs.post { _ = try self.remaining(5) }
        }
        try stage("android-existing-protected-copy-full-readback") {
            let catalog = try waitElement(named(renderer, "Protected Android tools on this Mac"), in: renderer)
            try press(catalog, "Refresh tool list", renderer: renderer, timeout: 48)
            _ = try waitElement(catalog.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "Tool catalog: ready.")), in: catalog, timeout: 48)
            let text = try androidPublicText(catalog)
            let instance = try Self.androidMatch(#"(?m)^Instance[ \n]+([0-9a-f]{32})[ \n]+· observed catalog"#, in: text)
            try require(text.contains("Gradle 8.14.5 · Android plugin 8.9.2 · android-35 · build tools 35.0.0."),
                        "Android existing protected tuple differs")
            // A unique actual current copy is a prerequisite, not created by this test.
            try press(catalog, "Recover (full verification)", renderer: renderer, timeout: 120)
            _ = try waitElement(catalog.staticTexts.matching(identifier:
                "Full original readback verified in this session. Choose is still a separate action; Build admits the originals again."),
                in: catalog, timeout: 120)
            try require(try Self.androidMatch(#"(?m)^Instance[ \n]+([0-9a-f]{32})[ \n]+· observed catalog"#,
                in: androidPublicText(catalog)) == instance, "Android protected original changed during recovery")
            try press(catalog, "Choose this tool copy", renderer: renderer, timeout: 48)
            _ = try waitElement(catalog.buttons.matching(identifier: "This copy is selected"), in: catalog, timeout: 48)
            try fixture.assertUnchanged()
        }
        try stage("android-memory-input-assignment") {
            try press(renderer, "Credentials", renderer: renderer)
            let storage = try waitElement(named(renderer, "Private-input storage controls"), in: renderer)
            try select(storage, label: "Platform", value: "Android", renderer: renderer)
            try select(storage, label: "Release stage", value: "Candidate / internal testing", renderer: renderer)
            try select(storage, label: "Input purpose", value: "Build / signing only", renderer: renderer)
            try press(storage, "Start session — keep inputs in memory", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "open")
            try privateContext(storage, renderer: renderer)
            try privateRecordCount(storage, count: 0, assigned: 0)
            try select(storage, label: "What would you like to provide?", value: "Android upload keystore", renderer: renderer)
            try select(storage, label: "New or replacement copy?", value: "Keep a new session record", renderer: renderer)
            try press(storage, "Select file…", renderer: renderer, failures: Self.privateInputFailures)
            let sheet = try nativeSheet(window, title: "Choose a signing or iOS build-input file")
            try goToFolder(sheet, path: initialInputs.credentialPath())
            let selected = try waitElement(controls(sheet, [.cell, .outlineRow, .tableRow, .icon], label: "upload.jks"), in: sheet, enabled: true)
            try require(selected.isHittable, "Android owned JKS picker item unavailable")
            selected.click(); try require(selected.isSelected, "Android owned JKS picker selection missing")
            try nativeOpen(sheet); try privateStatus(storage, action: "choose-file", phase: "selected")
            for (label, key) in [("Keystore password", "storePassword"), ("Private-key alias", "alias"), ("Private-key password", "keyPassword")] {
                let control = try waitElement(controls(storage, [.secureTextField], label: label, prefix: true),
                                              in: storage, enabled: true, failures: Self.privateInputFailures)
                try reveal(control, in: renderer); control.click()
                // All three ordinary fields are write-only. Never inspect or print value.
                control.typeText(try initialInputs.scalar(key))
            }
            try press(storage, "Prepare private review", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "prepare", phase: "preview")
            let review = try privateReview(storage, title: "Keep this input for this session?", target: "New android upload keystore session record")
            try press(review, "Keep for this session", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "commit")
            let row = try waitElement(named(storage, "Private input · Android upload keystore · item 1"), in: storage, failures: Self.privateInputFailures)
            try privateValue(storage, row, label: "Private-input record revision", value: "1")
            try privateRecordCount(storage, count: 1, assigned: 0)
            try press(row, "Review assignment", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "prepare", phase: "preview")
            let assignment = try privateReview(storage, title: "Assign this record to the submitted context?", target: "Android upload keystore · item 1 · revision 1")
            try press(assignment, "Assign to this context", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "bind")
            try privateRecordCount(storage, count: 1, assigned: 1)
            try fixture.assertUnchanged(); try initialInputs.post { _ = try self.remaining(5) }
        }
        var identity: LocalFixture.AndroidBuildIdentity?
        try stage("android-one-signed-build-original") {
            try press(renderer, "Releases", renderer: renderer)
            let signing = try waitElement(renderer.checkBoxes.matching(identifier: "Sign locally with my upload key"), in: renderer, enabled: true)
            try require((signing.value as? String) == "0" || (signing.value as? NSNumber)?.intValue == 0,
                        "Android signing must start opt-in")
            try reveal(signing, in: renderer); signing.click()
            _ = try waitElement(renderer.staticTexts.matching(identifier:
                "Current inputs are assigned. Passwords, private-key use and certificate policy will be checked during the owned run; file-format assessment alone is not signing verification."), in: renderer)
            try press(renderer, "Review saved inputs", renderer: renderer, timeout: 48)
            let review = try waitElement(controls(renderer, [.group], label: "Confirm this saved Android-build intent"), in: renderer, timeout: 48)
            let text = try androidPublicText(review)
            for fact in ["org.example.saved", ":app", "release", "1.2.3", "build", "7", certificate,
                         try fixture.androidSavedDigest(LocalFixture.config), try fixture.androidSavedDigest(LocalFixture.version)] {
                try require(text.contains(fact), "Android signed review saved-input binding differs")
            }
            let original = try androidCurrentBuildIdentity(review)
            identity = original
            try fixture.beginAndroidOutputObservation(original) { _ = try self.remaining(5) }
            let consent = try unique(review.checkBoxes.matching(NSPredicate(format: "label BEGINSWITH %@",
                "I trust this project and authorize one build")), "Android one-build consent unavailable")
            try require((consent.value as? String) == "0" || (consent.value as? NSNumber)?.intValue == 0,
                        "Android build consent unexpectedly checked")
            try reveal(consent, in: renderer); consent.click()
            try require(try androidCurrentBuildIdentity(review) == original, "Android consent identity changed")
            try fixture.confirmAndroidStart(original) { _ = try self.remaining(5) }
            try press(review, "Build, sign and validate", renderer: renderer, timeout: 48) // The sole Start.
        }
        guard let identity else { throw Refusal.condition("Android original build identity missing") }
        var artifact: (Int, String)?
        try stage("android-known-native-terminal") {
            let status = try waitElement(named(renderer, "Original Android build status"), in: renderer, timeout: 48)
            try require(try androidCurrentBuildIdentity(status) == identity, "Android running original identity differs")
            try fixture.assertAndroidRunning(identity) { _ = try self.remaining(5) }
            let terminal = try waitElement(named(renderer, "Completed local Android AAB observation"), in: renderer,
                timeout: try remaining(780), failures: ["No new Android-build outcome was confirmed", "Cleanup needs attention",
                "The original request acknowledgement is unconfirmed. Do not repeat Start. Original Status may help cancel or settle that operation, but cannot create new consent."])
            _ = try waitElement(status.staticTexts.matching(identifier:
                "Task work: removed. Local artifacts: retained-local-result. Disposition is not permission for blanket deletion or a rerun."), in: status)
            try require(try androidCurrentBuildIdentity(status) == identity, "Android terminal status identity differs")
            artifact = try androidResult(terminal, identity: identity, certificate: certificate)
            // Original private POST -> ALL18 consuming closes -> clock -> drop
            // scalar-owning references. No private reopening after this boundary.
            try initialInputs.finish { _ = try self.remaining(5) }
            try require(initialInputs.terminalClose, "Android private original close unconfirmed")
            ownedAndroidInputs = nil; inputs = nil
            try press(renderer, "Credentials", renderer: renderer)
            let storage = try waitElement(named(renderer, "Private-input storage controls"), in: renderer)
            try press(storage, "Discard session…", renderer: renderer, failures: Self.privateInputFailures)
            let discard = try waitElement(named(storage, "Confirm private-input lock"), in: storage, failures: Self.privateInputFailures)
            try press(discard, "Discard session copies", renderer: renderer, failures: Self.privateInputFailures)
            try privateStatus(storage, action: "lock")
            _ = try waitElement(storage.staticTexts.matching(identifier: "Storage closed"), in: storage, failures: Self.privateInputFailures)
            try privateRecordCount(storage, count: 0, assigned: 0)
        }
        guard let artifact else { throw Refusal.condition("Android native artifact observation missing") }
        var summary: LocalFixture.AndroidOutputSummary?
        try stage("android-output-census-and-normal-quit") {
            summary = try fixture.finishAndroidOutputObservation(identity, artifactBytes: Int64(artifact.0), artifactSHA256: artifact.1) {
                _ = try self.remaining(5)
            }
            try press(renderer, "Artifacts", renderer: renderer)
            let result = try waitElement(named(renderer, "Completed local Android AAB observation"), in: renderer)
            let repeated = try androidResult(result, identity: identity, certificate: certificate)
            try require(repeated.0 == artifact.0 && repeated.1 == artifact.1, "Android Artifacts observation changed")
            try fixture.assertAndroidOutputClosure(identity) { _ = try self.remaining(5) }
            let sheet = try quitSheet(app, window)
            try click(sheet.buttons.matching(identifier: "Quit"), "Android ordinary Quit unavailable")
            try completeNormalQuit(app)
            try fixture.closeAndroidOriginals(identity) { _ = try self.remaining(5) }
            ownedFixture = nil
        }
        guard let summary else { throw Refusal.condition("Android final output census missing") }
        try acceptFinalScenario()
        let env = ProcessInfo.processInfo.environment
        let facts: [String: Any] = ["schemaVersion": 1, "scope": "one-ordinary-local-signed-android-build",
            "sourceCommit": env["MRK_NORMAL_UI_HARNESS_SOURCE"] ?? "", "target": "aarch64-apple-darwin",
            "runId": env["MRK_NORMAL_UI_ANDROID_RUN_ID"] ?? "", "runAttempt": env["MRK_NORMAL_UI_ANDROID_RUN_ATTEMPT"] ?? "",
            "sourceRegistrationObserved": false, "nativeSigningVerified": true, "privateOriginalsClosed": true,
            "memorySessionDiscarded": true, "outputPostMatched": true, "normalQuitObserved": true,
            "releaseQualified": false, "parentReturncodeRequired": 0, "operationId": identity.operationID,
            "ownerGeneration": identity.ownerGeneration, "publicCertificateSha256": certificate,
            "artifactSha256": artifact.1, "artifactBytes": artifact.0, "outputEntries": summary.entries,
            "outputNameBytes": summary.nameBytes, "outputLogicalBytes": summary.logicalBytes,
            "moduleLogicalBytes": summary.moduleBytes, "outputCensusSha256": summary.censusSHA256]
        let raw = try JSONSerialization.data(withJSONObject: facts, options: [.sortedKeys, .withoutEscapingSlashes])
        try require(raw.count <= 16 * 1024, "Android safe public result bound")
        _ = try remaining(5)
        print("MRK_MACOS_ANDROID_SIGNED_BUILD_UI=" + String(decoding: raw, as: UTF8.self))
    }

    override func tearDown() async throws {
        var cleanupFailure: Error?
        do {
            try await MainActor.run {
                if let owner = originalLaunch {
                    if removalQuitObserved {
                        guard !normalQuitObserved && completedPersistenceLifetime == nil else {
                            throw Refusal.condition("removal teardown has conflicting terminal origins")
                        }
                        // Actual removal-origin exit; never relabel it normal UI Quit.
                        try owner.acceptTerminal()
                    } else { try owner.tearDown(normalQuit: normalQuitObserved) }
                }
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
        // The task channel is closed independently even after setup/UI failure.
        // No marker, directory or possibly live task output is deleted here.
        do { try await MainActor.run { try removalChannel?.closeOriginals() } }
        catch { if cleanupFailure == nil { cleanupFailure = error } }
        // Independent private consuming close after any partial setup or unknown
        // native operation. This is NOT successful private POST/session disposal.
        do {
            try await MainActor.run {
                if let inputs = ownedAndroidInputs {
                    ownedAndroidInputs = nil
                    try inputs.close { _ = try self.remaining(5) }
                }
            }
        } catch { if cleanupFailure == nil { cleanupFailure = error } }
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
