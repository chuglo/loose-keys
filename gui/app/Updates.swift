// Asking GitHub whether a newer Loose Keys is out. This is the app's only
// network code: a test in gui/src/release.rs keeps it in this file. It
// fetches the reply; the engine reads it (check_release).
import Foundation

/// Where the description of the latest release comes from.
protocol ReleaseSource: Sendable {
    func latest() async throws -> Data
}

/// For builds that never go online: the sample window, the picture build
/// and the model check.
struct NoReleases: ReleaseSource {
    func latest() async throws -> Data {
        throw EngineError(message: String(localized: "Update checks are not available in this build.",
                                          comment: "In an alert after Check for Updates… in a test build of the app, which never goes online."))
    }
}

enum Releases {
    /// What Download opens: GitHub's page for the latest release.
    static let page = URL(string: "https://github.com/chuglo/loose-keys/releases/latest")!
    /// One automatic check a day while the app runs, by the wall clock.
    static let interval: TimeInterval = 86_400
    /// How often the automatic checks look whether a day has passed.
    static let look: UInt64 = 3_600_000_000_000
    /// The most of GitHub's reply that is read. The engine checks it again.
    static let limit = 1_048_576
}

#if !PREVIEW
/// One GET of GitHub's latest-release API. It sends what any HTTPS request
/// does, and no cookie, cached reply, saved password or followed redirect.
final class GitHubReleases: ReleaseSource {
    private static let api = URL(string: "https://api.github.com/repos/chuglo/loose-keys/releases/latest")!
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
    }

    func latest() async throws -> Data {
        var request = URLRequest(url: Self.api)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("LooseKeys", forHTTPHeaderField: "User-Agent")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, http.url?.scheme == "https",
              http.url?.host == Self.api.host else {
            throw Self.notExpected
        }
        guard http.statusCode == 200 else {
            throw EngineError(message: String(localized: "GitHub answered with an error (\(http.statusCode)).",
                                              comment: "In an alert after Check for Updates…. %lld is the HTTP status code GitHub sent."))
        }
        guard http.expectedContentLength <= Int64(Releases.limit) else { throw Self.notExpected }
        var data = Data()
        for try await byte in bytes {
            guard data.count < Releases.limit else { throw Self.notExpected }
            data.append(byte)
        }
        return data
    }

    private static var notExpected: EngineError {
        EngineError(message: String(localized: "GitHub's answer was not in the expected form.",
                                    comment: "In an alert after Check for Updates…: GitHub's reply was too long or came from somewhere else."))
    }
}

/// Answers a redirect with the redirect itself, which then fails as a reply
/// that is not 200, so the request never reaches another address.
private final class NoRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
#endif
