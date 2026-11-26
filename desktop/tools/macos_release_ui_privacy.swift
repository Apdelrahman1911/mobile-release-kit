import Foundation
import Vision

struct Reading: Encodable {
    let text: String
    let x: Double
    let y: Double
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
