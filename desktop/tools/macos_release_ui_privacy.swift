import AppKit
import ApplicationServices
import Foundation
import Vision

struct Reading: Encodable {
    let text: String
    let x: Double
    let y: Double
}

struct GitControl: Encodable {
    var regions = 0
    var matches = 0
    var enabled: Bool? = nil
    var checked: Bool? = nil
    var pressed = false
    var error: String? = nil
}

func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success ? value : nil
}

func named(_ element: AXUIElement, _ name: String, includeValue: Bool = false) -> Bool {
    let attributes = [kAXTitleAttribute, kAXDescriptionAttribute] + (includeValue ? [kAXValueAttribute] : [])
    return attributes.contains { (attribute(element, $0) as? String) == name }
}

func matching(_ root: AXUIElement, limit: Int, predicate: (AXUIElement) -> Bool) -> [AXUIElement]? {
    var work = attribute(root, kAXChildrenAttribute) as? [AXUIElement] ?? []
    var matches: [AXUIElement] = []
    var seen = 0
    while let element = work.popLast() {
        seen += 1
        guard seen + work.count <= limit else { return nil }
        if predicate(element) {
            matches.append(element)
            if matches.count > 1 { return matches }
        }
        work.append(contentsOf: attribute(element, kAXChildrenAttribute) as? [AXUIElement] ?? [])
    }
    return matches
}

func inspectGitReview(_ arguments: [String]) -> GitControl {
    guard arguments.count == 5, let pid = Int32(arguments[0]), pid > 0 else { return GitControl(error: "arguments") }
    let (region, role, name, action) = (arguments[1], arguments[2], arguments[3], arguments[4])
    guard ["Review local Git change", "Local Git action status", "Local Git changes", "Local Git read status"].contains(region),
          ["AXHeading", "AXStaticText", "AXButton", "AXCheckBox"].contains(role),
          ["inspect", "press"].contains(action) else { return GitControl(error: "scope") }
    guard AXIsProcessTrusted() else { return GitControl(error: "ax-unavailable") }
    guard NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else { return GitControl(error: "not-frontmost") }
    let application = AXUIElementCreateApplication(pid)
    guard AXUIElementSetMessagingTimeout(application, 2) == .success,
          let windows = attribute(application, kAXWindowsAttribute) as? [AXUIElement],
          windows.count == 1 else { return GitControl(error: "window") }
    guard let regions = matching(windows[0], limit: 4096, predicate: { element in
        let role = attribute(element, kAXRoleAttribute) as? String
        return ["AXGroup", "AXLandmarkRegion"].contains(role ?? "") && named(element, region)
    }) else { return GitControl(error: "window-bound") }
    guard regions.count == 1 else { return GitControl(regions: regions.count) }
    guard let controls = matching(regions[0], limit: 256, predicate: { element in
        (attribute(element, kAXRoleAttribute) as? String) == role && named(element, name, includeValue: role == "AXStaticText")
    }) else { return GitControl(error: "region-bound") }
    guard controls.count == 1 else { return GitControl(regions: 1, matches: controls.count) }
    let control = controls[0]
    var result = GitControl(regions: 1, matches: 1)
    result.enabled = (attribute(control, kAXEnabledAttribute) as? NSNumber)?.boolValue
    if role == "AXCheckBox", let value = attribute(control, kAXValueAttribute) as? NSNumber, [0, 1].contains(value.intValue) {
        result.checked = value.boolValue
    }
    if action == "press", result.enabled == true, ["AXButton", "AXCheckBox"].contains(role),
       NSWorkspace.shared.frontmostApplication?.processIdentifier == pid {
        result.pressed = AXUIElementPerformAction(control, kAXPressAction as CFString) == .success
    }
    return result
}

if CommandLine.arguments.dropFirst().first == "git-review" {
    let result = inspectGitReview(Array(CommandLine.arguments.dropFirst(2)))
    FileHandle.standardOutput.write(try JSONEncoder().encode(result))
    exit(0)
}

let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.recognitionLanguages = ["en-US"]
let url = URL(fileURLWithPath: CommandLine.arguments[1])
try VNImageRequestHandler(url: url).perform([request])
let readings = (request.results ?? []).compactMap { observation -> Reading? in
    guard let text = observation.topCandidates(1).first?.string else { return nil }
    let bounds = observation.boundingBox
    return Reading(text: text, x: bounds.midX, y: 1 - bounds.midY)
}
FileHandle.standardOutput.write(try JSONEncoder().encode(readings))
