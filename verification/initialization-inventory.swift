import AppKit
import ApplicationServices
import Foundation

struct Inventory: Encodable {
    var tableRows: Int = 0
    var matchingPaths: [Bool] = []
    var error: String?
}

struct Action: Encodable {
    var matches: Int = 0
    var pressed: Bool = false
    var error: String?
}

func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success ? value : nil
}

func nodes(_ root: AXUIElement, limit: Int) -> [AXUIElement]? {
    var pending = [root]
    var visited: [AXUIElement] = []
    while let node = pending.popLast() {
        if visited.contains(where: { CFEqual($0, node) }) { continue }
        guard visited.count + pending.count < limit else { return nil }
        visited.append(node)
        for relation in [kAXChildrenAttribute, kAXRowsAttribute] {
            let subset = attribute(node, relation) as? [AXUIElement] ?? []
            guard subset.count < limit else { return nil }
            pending.append(contentsOf: subset)
        }
    }
    return visited
}

func initializationNodes(_ pid: Int32) -> [AXUIElement]? {
    guard AXIsProcessTrusted(), NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else {
        return nil
    }
    let app = AXUIElementCreateApplication(pid)
    guard AXUIElementSetMessagingTimeout(app, 2) == .success,
          let windows = attribute(app, kAXWindowsAttribute) as? [AXUIElement], windows.count == 1,
          let window = nodes(windows[0], limit: 1000) else { return nil }
    let regions = window.filter { element in
        let role = attribute(element, kAXRoleAttribute) as? String
        return ["AXGroup", "AXLandmarkRegion"].contains(role ?? "") &&
            [kAXTitleAttribute, kAXDescriptionAttribute].contains { attribute(element, $0) as? String == "Project initialization" }
    }
    guard regions.count == 1 else { return nil }
    return nodes(regions[0], limit: 420)
}

func inspect(_ argv: [String]) -> Inventory {
    guard argv.count == 15, let pid = Int32(argv[0]), pid > 0 else { return Inventory(error: "arguments") }
    let paths = Array(argv.dropFirst())
    guard Set(paths).count == paths.count,
          paths.allSatisfy({ $0.range(of: #"^[a-zA-Z0-9._/-]{1,120}$"#, options: .regularExpression) != nil }) else {
        return Inventory(error: "path-shape")
    }
    guard let region = initializationNodes(pid) else { return Inventory(error: "original-region") }
    let tables = region.filter { attribute($0, kAXRoleAttribute) as? String == "AXTable" }
    guard tables.count == 1, let table = nodes(tables[0], limit: 240) else { return Inventory(error: "table") }
    let rows = table.filter { attribute($0, kAXRoleAttribute) as? String == "AXRow" }
    var observed = Set<String>()
    for node in table {
        for property in [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute] {
            if let value = attribute(node, property) as? String, paths.contains(value) { observed.insert(value) }
        }
    }
    guard NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else { return Inventory(error: "application-changed") }
    return Inventory(tableRows: rows.count, matchingPaths: paths.map { observed.contains($0) })
}

func normalized(_ value: String) -> String {
    value.split(whereSeparator: \.isWhitespace).joined(separator: " ")
}

func act(_ arguments: [String]) -> Action {
    guard arguments.count == 2, let pid = Int32(arguments[0]), pid > 0 else { return Action(error: "arguments") }
    let action = arguments[1]
    let consent = "I reviewed the complete plan above and confirm these local file creations and ignore additions."
    guard let region = initializationNodes(pid) else { return Action(error: "original-region") }
    let controls = region.filter { element in
        let title = [kAXTitleAttribute, kAXDescriptionAttribute, kAXTitleUIElementAttribute].compactMap { property -> String? in
            if property == kAXTitleUIElementAttribute,
               let label = attribute(element, property), CFGetTypeID(label) == AXUIElementGetTypeID() {
                let linked = unsafeDowncast(label, to: AXUIElement.self)
                return attribute(linked, kAXValueAttribute) as? String
            }
            return attribute(element, property) as? String
        }.map(normalized)
        let role = attribute(element, kAXRoleAttribute) as? String
        return action == "consent" && role == "AXCheckBox" && title.contains(consent)
            || action == "confirm" && role == "AXButton" && title.contains("Initialize project")
    }
    guard controls.count == 1 else { return Action(matches: controls.count, error: "control-count") }
    let control = controls[0]
    guard (attribute(control, kAXEnabledAttribute) as? NSNumber)?.boolValue == true else {
        return Action(matches: 1, error: "disabled")
    }
    if action == "consent", (attribute(control, kAXValueAttribute) as? NSNumber)?.intValue != 0 {
        return Action(matches: 1, error: "consent-not-fresh")
    }
    guard NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else {
        return Action(matches: 1, error: "application-changed")
    }
    let pressed = AXUIElementPerformAction(control, kAXPressAction as CFString) == .success
    return Action(matches: 1, pressed: pressed, error: pressed ? nil : "ax-press")
}

let arguments = Array(CommandLine.arguments.dropFirst())
if arguments.count == 2, ["consent", "confirm"].contains(arguments[1]) {
    FileHandle.standardOutput.write(try JSONEncoder().encode(act(arguments)))
} else {
    FileHandle.standardOutput.write(try JSONEncoder().encode(inspect(arguments)))
}
