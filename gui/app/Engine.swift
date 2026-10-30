// The scanner and review store, reached one command at a time.
import Foundation

/// A refusal or failure, as the engine or the window wrote it. What is shown
/// is in the window's language: the engine's English is looked up there.
struct EngineError: LocalizedError {
    let message: String
    var errorDescription: String? { EngineText.shown(message) }
}

protocol Engine: AnyObject {
    /// Start the engine. Events may arrive on any thread.
    func start(reviewRoute: Bool, onEvent: @escaping (String, Data) -> Void)
    /// Blocks until the command finishes. Returns the JSON of its result.
    func call(_ command: String, _ args: [String: Any]) throws -> Data
}

func decodeEngine<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return try decoder.decode(type, from: data)
}

extension Engine {
    /// Run a command off the main thread and decode what it returns.
    func request<T: Decodable>(_ command: String, _ args: [String: Any] = [:]) async throws -> T {
        let data = try await Task.detached(priority: .userInitiated) { [self] in
            try self.call(command, args)
        }.value
        return try decodeEngine(T.self, from: data)
    }

    /// Run a command whose result is not needed.
    func send(_ command: String, _ args: [String: Any] = [:]) async throws {
        _ = try await Task.detached(priority: .userInitiated) { [self] in
            try self.call(command, args)
        }.value
    }
}

#if !PREVIEW
/// A C callback cannot carry context, so the handler lives here.
private var eventSink: ((String, Data) -> Void)?

/// The Rust engine linked into this executable (Bridge.h).
final class LiveEngine: Engine {
    func start(reviewRoute: Bool, onEvent: @escaping (String, Data) -> Void) {
        eventSink = onEvent
        ch_set_event_handler { name, payload in
            guard let name, let payload else { return }
            eventSink?(String(cString: name), Data(String(cString: payload).utf8))
        }
        ch_app_start(reviewRoute)
    }

    func call(_ command: String, _ args: [String: Any]) throws -> Data {
        let json = String(decoding: try JSONSerialization.data(withJSONObject: args), as: UTF8.self)
        guard let raw = ch_call(command, json) else {
            throw EngineError(message: String(localized: "Loose Keys stopped responding. Try again.",
                                              comment: "In an alert: the engine linked into the app returned nothing for a request."))
        }
        defer { ch_free(raw) }
        let reply = try JSONSerialization.jsonObject(with: Data(String(cString: raw).utf8))
        guard let reply = reply as? [String: Any] else {
            throw EngineError(message: String(localized: "Something went wrong inside Loose Keys. Try again.",
                                              comment: "In an alert: the engine's answer to a request was not in the form the window expects."))
        }
        if let error = reply["error"] as? String {
            throw EngineError(message: error)
        }
        return try JSONSerialization.data(withJSONObject: reply["ok"] ?? NSNull(), options: [.fragmentsAllowed])
    }
}
#endif
