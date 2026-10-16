// A nonprivileged convenience entry, not an installation or runtime authority.
// Integrated /Applications publication is not implemented by this component.
import AppKit
import Darwin
import Foundation
import Security

private enum InstalledApplication {
    static let url = URL(fileURLWithPath:
        "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app",
        isDirectory: true)
    static let requirement = """
        anchor apple generic and identifier "dev.mobile-release-kit.desktop.entry" \
        and certificate leaf[subject.OU] = "7CGZ2343AA" \
        and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
        and certificate leaf[field.1.2.840.113635.100.6.1.13] exists
        """

    // Security validates this fixed protected URL. The result is only a launch
    // precheck, never passed to the real entry as an authorization capability.
    // The entry independently reacquires its maintenance lock and clean runtime.
    static func signatureIsValid() -> Bool {
        var code: SecStaticCode?
        var rule: SecRequirement?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code,
              SecRequirementCreateWithString(requirement as CFString, [], &rule) == errSecSuccess,
              let rule else { return false }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures
            | kSecCSCheckNestedCode | kSecCSNoNetworkAccess)
        return SecStaticCodeCheckValidity(code, flags, rule) == errSecSuccess
    }
}

@MainActor
private final class Launcher: NSObject, NSApplicationDelegate {
    private let startupLimit: TimeInterval = 15
    private var deadline: TimeInterval = 0
    private var completed = false
    private var timeout: DispatchWorkItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard getuid() != 0, getuid() == geteuid(), getgid() == getegid(), issetugid() == 0 else {
            finish(message: "Open Mobile Release Kit from your normal macOS account, not as an administrator process.")
            return
        }
        guard CommandLine.arguments.count == 1 else {
            finish(message: "This launcher opens only the installed Mobile Release Kit application. It does not accept files, commands or additional arguments.")
            return
        }
        deadline = ProcessInfo.processInfo.systemUptime + startupLimit
        let timer = DispatchWorkItem { [weak self] in self?.timedOut() }
        timeout = timer
        DispatchQueue.main.asyncAfter(deadline: .now() + startupLimit, execute: timer)
        // The blocking Security API cannot stall the main run loop or renew the
        // startup deadline. A late result cannot submit a new launch request.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let valid = InstalledApplication.signatureIsValid()
            DispatchQueue.main.async { [weak self] in self?.signatureFinished(valid) }
        }
    }

    private func signatureFinished(_ valid: Bool) {
        guard !completed else { return }
        guard ProcessInfo.processInfo.systemUptime < deadline else { timedOut(); return }
        guard valid else {
            finish(message: "The installed Mobile Release Kit application could not be verified. Install the matching signed application package first. Keep its protected app in its original location; do not replace it with a copied bundle.")
            return
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        configuration.arguments = []
        configuration.environment = [:]
        // Do not activate a same-identifier application at some different URL.
        configuration.allowsRunningApplicationSubstitution = false
        configuration.createsNewApplicationInstance = false
        configuration.promptsUserIfNeeded = true
        NSWorkspace.shared.openApplication(at: InstalledApplication.url,
            configuration: configuration) { [weak self] application, error in
            let confirmed = application != nil && error == nil
            // AppKit documents this callback on a concurrent queue. Neither
            // NSRunningApplication nor raw NSError is retained or logged.
            DispatchQueue.main.async { [weak self] in self?.launchFinished(confirmed) }
        }
    }

    private func launchFinished(_ confirmed: Bool) {
        guard !completed else { return }
        guard ProcessInfo.processInfo.systemUptime < deadline else { timedOut(); return }
        finish(message: confirmed ? nil : "macOS did not confirm the application launch. Check whether Mobile Release Kit has opened before trying again. If it has not, check the installed application or use its matching installer.")
    }

    private func timedOut() {
        finish(message: "Opening Mobile Release Kit was not confirmed within 15 seconds. A submitted macOS launch request may still complete. Check for the application before trying again; this launcher has not stopped or modified it.")
    }

    private func finish(message: String?) {
        guard !completed else { return }
        completed = true
        timeout?.cancel()
        timeout = nil
        if let message {
            let alert = NSAlert()
            alert.messageText = "Mobile Release Kit could not be opened"
            alert.informativeText = message
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            NSApplication.shared.activate(ignoringOtherApps: true)
            alert.runModal()
        }
        // Terminate only this convenience launcher. Never terminate or retry a
        // target app, an OS launch request, or another task's process.
        NSApplication.shared.terminate(nil)
    }
}

private let application = NSApplication.shared
private let launcher = Launcher()
application.delegate = launcher
application.setActivationPolicy(.accessory)
application.run()
