import XCTest
import Security

/// Records golden verdicts for the shared fixture CA tree (shared/fixtures/ca) into shared/golden.
/// Skipped unless CC_GOLDEN_OUT is set (shared/tools/record-golden.sh sets it), so test.sh is unaffected.
/// Read-only use of FileCheck; the only extra is a second SecTrust evaluation anchored at the fixture root.
/// Titles carry dates from Analysis.fmt, so the recorder pins TZ=UTC and en_US; this test refuses any other zone.
final class GoldenExportTests: PinnedTestCase {
    func testRecordGolden() throws {
        let env = ProcessInfo.processInfo.environment
        guard let outPath = env["CC_GOLDEN_OUT"], let fxPath = env["CC_GOLDEN_FIXTURES"] else {
            throw XCTSkip("CC_GOLDEN_OUT / CC_GOLDEN_FIXTURES not set")
        }
        continueAfterFailure = false
        XCTAssertTrue(["UTC", "GMT"].contains(TimeZone.current.identifier), "record with TZ=UTC so title dates are stable (got \(TimeZone.current.identifier))")
        XCTAssertEqual(Locale.current.identifier, "en_US", "record with the en_US locale")
        let iso = ISO8601DateFormatter()  // UTC, e.g. 2026-01-01T00:00:00Z
        let fx = URL(fileURLWithPath: fxPath), out = URL(fileURLWithPath: outPath)
        let manifestAny = try JSONSerialization.jsonObject(with: Data(contentsOf: fx.appendingPathComponent("cases.json")))
        let manifest = try XCTUnwrap(manifestAny as? [String: Any], "cases.json is not an object")
        let pinned = try XCTUnwrap(manifest["pinned_now"] as? String, "pinned_now missing")
        let now = try XCTUnwrap(iso.date(from: pinned), "pinned_now is not ISO 8601")
        let rootName = try XCTUnwrap(manifest["root"] as? String, "root missing")
        try Self.checkName(rootName)
        let anchor = try XCTUnwrap(SecCertificateCreateWithData(nil, Data(try Self.der(fx.appendingPathComponent(rootName))) as CFData),
                                   "fixture root is not a certificate")
        let cases = try XCTUnwrap(manifest["cases"] as? [[String: Any]], "cases missing")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        for c in cases {
            let name = try XCTUnwrap(c["name"] as? String, "case without name")
            try Self.checkName(name)
            let host = try XCTUnwrap(c["hostname"] as? String, "\(name): hostname missing")
            let purposeName = try XCTUnwrap(c["purpose"] as? String, "\(name): purpose missing")
            let purpose: Purpose = purposeName == "client" ? .tlsClient : .tlsServer
            let files = try XCTUnwrap(c["files"] as? [String], "\(name): files missing")
            try files.forEach(Self.checkName)
            let dir = fx.appendingPathComponent("cases").appendingPathComponent(name)
            let r = FileCheck.inspect(files.map { dir.appendingPathComponent($0) }, hostname: host, purpose: purpose, now: now)
            let findings: [[String: String]] = r.findings.map {
                ["id": $0.id, "severity": $0.severity.label.lowercased(), "topic": $0.topic.rawValue, "kind": $0.kind, "title": $0.title]
            }
            // Same policy as Trust.evaluate, but with the fixture root as the only anchor.
            let sec = r.chain.compactMap { SecCertificateCreateWithData(nil, Data($0.der) as CFData) }
            XCTAssertEqual(sec.count, r.chain.count, "\(name): chain certificate rejected by Security")
            var trustRef: SecTrust?
            XCTAssertEqual(SecTrustCreateWithCertificates(sec as CFArray, SecPolicyCreateSSL(purpose == .tlsServer, host as CFString), &trustRef), errSecSuccess)
            let trust = try XCTUnwrap(trustRef, "\(name): SecTrust not created")
            SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            SecTrustSetNetworkFetchAllowed(trust, false)
            SecTrustSetVerifyDate(trust, now as CFDate)
            var err: CFError?
            let ok = SecTrustEvaluateWithError(trust, &err)
            let doc: [String: Any] = [
                "schema": 1, "case": name, "hostname": host, "purpose": purposeName,
                "pinned_now": pinned, "recorded_by": "macOS FileCheck + SecTrust",
                "recorded_tz": TimeZone.current.identifier, "recorded_locale": Locale.current.identifier,
                "findings": findings,
                "chain_sha256": r.chain.map { $0.sha256 },
                // Machine-readable dates (ISO 8601 UTC); titles keep the localised display dates.
                "chain_validity": r.chain.map { ["not_before": iso.string(from: $0.notBefore), "not_after": iso.string(from: $0.notAfter)] },
                "trust_fixture_anchor": ["trusted": ok, "error_code": err.map { CFErrorGetCode($0) } ?? 0],
            ]
            let data = try JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: out.appendingPathComponent("\(name).json"))
        }
    }

    /// Names from cases.json become path components; refuse anything that could leave the fixture tree.
    static func checkName(_ s: String) throws {
        if s.isEmpty || s.contains("/") || s.contains("..") || s.hasPrefix(".") {
            XCTFail("unsafe fixture name \(s)"); throw XCTSkip("unsafe fixture name")
        }
    }

    static func der(_ url: URL) throws -> [UInt8] {
        let text = try String(contentsOf: url, encoding: .utf8)
        let b64 = text.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
        return [UInt8](try XCTUnwrap(Data(base64Encoded: b64), "\(url.lastPathComponent) is not PEM"))
    }
}
