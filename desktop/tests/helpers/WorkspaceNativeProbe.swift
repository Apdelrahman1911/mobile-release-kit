// Isolated nonpersistent WebKit test host; never launches or controls the installed app.
import Cocoa
import WebKit

final class Probe: NSObject, WKScriptMessageHandler, WKURLSchemeHandler, WKNavigationDelegate {
    let root: URL
    var web: WKWebView!
    var host: NSWindow!
    var finished = false
    init(root: URL) { self.root = root.standardizedFileURL; super.init() }
    func start() {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        config.userContentController.add(self, name: "probe")
        config.userContentController.addUserScript(WKUserScript(source: """
        window.webkit.messageHandlers.probe.postMessage({trace:'document-start'});
        window.addEventListener('error', e => window.webkit.messageHandlers.probe.postMessage({ok:false,phase:'early-script-error',message:String(e.message || 'resource-load-error')}));
        window.addEventListener('unhandledrejection', e => window.webkit.messageHandlers.probe.postMessage({ok:false,phase:'early-rejection',message:String(e.reason && e.reason.message || e.reason)}));
        """, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        config.setURLSchemeHandler(self, forURLScheme: "mrktest")
        web = WKWebView(frame: NSRect(x: 0, y: 0, width: 1280, height: 900), configuration: config)
        web.navigationDelegate = self
        host = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 900), styleMask: [.borderless], backing: .buffered, defer: false)
        host.isReleasedWhenClosed = false
        host.ignoresMouseEvents = true
        host.alphaValue = 0
        host.contentView = web
        host.orderBack(nil)
        web.load(URLRequest(url: URL(string: "mrktest://app/index.html")!))
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in
            self?.end(["ok": false, "phase": "host-deadline"])
        }
    }
    func end(_ value: Any) {
        guard !finished else { return }; finished = true
        let data = (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])) ?? Data("{}".utf8)
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data("\n".utf8))
        web.stopLoading()
        let ok = (value as? [String: Any])?["ok"] as? Bool ?? false
        exit(ok ? 0 : 1)
    }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        if let trace = (message.body as? [String: Any])?["trace"] as? String {
            FileHandle.standardError.write(Data(("PROBE_TRACE=" + trace + "\n").utf8)); return
        }
        end(message.body)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        FileHandle.standardError.write(Data("PROBE_TRACE=navigation-finished\n".utf8))
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        end(["ok": false, "phase": "navigation", "code": (error as NSError).code])
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        end(["ok": false, "phase": "navigation", "code": (error as NSError).code])
    }
    func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
        guard let url = urlSchemeTask.request.url, url.host == "app",
              !url.path.split(separator: "/").contains("..") else {
            urlSchemeTask.didFailWithError(NSError(domain: "fixture", code: 1)); return
        }
        let path = root.appendingPathComponent(url.path).standardizedFileURL
        guard path.path.hasPrefix(root.path + "/"), let bytes = try? Data(contentsOf: path), bytes.count < 8 * 1024 * 1024 else {
            urlSchemeTask.didFailWithError(NSError(domain: "fixture", code: 2)); return
        }
        let types = ["html": "text/html", "js": "application/javascript", "css": "text/css", "json": "application/json", "svg": "image/svg+xml", "woff2": "font/woff2"]
        urlSchemeTask.didReceive(URLResponse(url: url, mimeType: types[path.pathExtension] ?? "application/octet-stream", expectedContentLength: bytes.count, textEncodingName: "utf-8"))
        urlSchemeTask.didReceive(bytes); urlSchemeTask.didFinish()
    }
    func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}
}
guard CommandLine.arguments.count == 2 else { exit(2) }
let application = NSApplication.shared
application.setActivationPolicy(.prohibited)
let probe = Probe(root: URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true))
probe.start()
application.run()
