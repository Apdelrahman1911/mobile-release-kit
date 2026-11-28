import AppKit
import ApplicationServices
import Foundation

struct Inventory: Encodable {
    var tableRows: Int = 0
    var matchingPaths: [Bool] = []
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

func inspect(_ argv: [String]) -> Inventory {
    guard argv.count == 15, let pid = Int32(argv[0]), pid > 0 else { return Inventory(error: "arguments") }
    let paths = Array(argv.dropFirst())
    guard Set(paths).count == paths.count,
          paths.allSatisfy({ $0.range(of: #"^[a-zA-Z0-9._/-]{1,120}$"#, options: .regularExpression) != nil }) else {
        return Inventory(error: "path-shape")
    }
    guard AXIsProcessTrusted(), NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else {
        return Inventory(error: "application")
    }
    let app = AXUIElementCreateApplication(pid)
    guard AXUIElementSetMessagingTimeout(app, 2) == .success,
          let windows = attribute(app, kAXWindowsAttribute) as? [AXUIElement], windows.count == 1,
          let window = nodes(windows[0], limit: 1000) else { return Inventory(error: "window") }
    let regions = window.filter { element in
        let role = attribute(element, kAXRoleAttribute) as? String
        return ["AXGroup", "AXLandmarkRegion"].contains(role ?? "") &&
            [kAXTitleAttribute, kAXDescriptionAttribute].contains { attribute(element, $0) as? String == "Project initialization" }
    }
    guard regions.count == 1, let region = nodes(regions[0], limit: 420) else { return Inventory(error: "region") }
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

FileHandle.standardOutput.write(try JSONEncoder().encode(inspect(Array(CommandLine.arguments.dropFirst()))))
