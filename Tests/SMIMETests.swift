import XCTest
/// S/MIME (0.9.0). SYNTHETIC-smime-* fixtures from make-smime-fixtures.sh; offline only.
final class SMIMETests: PinnedTestCase {
    func c(_ n: String) throws -> Certificate {
        let u = CertificateCheckerTests.fixtures.appendingPathComponent("SYNTHETIC-smime-\(n).pem")
        return try Certificate(der: PEM.blocks(String(decoding: try Data(contentsOf: u), as: UTF8.self))[0].der)
    }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }
    /// A fixed "now" inside each certificate's validity, so the tests never depend on the wall clock.
    func run(_ n: String, address: String? = nil, daysLeft: Double = 200) throws -> [Finding] {
        let cert = try c(n); return SMIME.inspect(cert, address: address, now: cert.notAfter.addingTimeInterval(-daysLeft * 86_400))
    }

    func testGood() throws {
        let f = try run("good", address: "Alice@Example.test")
        for id in ["smime-eku", "smime-ku-sign", "smime-ku-encrypt", "smime-address", "smime-expiry", "smime-key"] { XCTAssertEqual(sev(f, id), .pass, id) }
        XCTAssertFalse(f.contains { $0.severity == .fail })
    }
    func testWrongAddress() throws { XCTAssertEqual(sev(try run("good", address: "bob@example.test"), "smime-address"), .fail) }
    func testSignOnly() throws { XCTAssertEqual(sev(try run("signonly"), "smime-ku-encrypt"), .info) }
    func testServerEKU() throws { XCTAssertEqual(sev(try run("server"), "smime-eku"), .fail) }
    func testSoon() throws { XCTAssertEqual(sev(try run("soon", daysLeft: 5), "smime-expiry"), .warning) }
    func testExpired() throws { XCTAssertEqual(sev(SMIME.inspect(try c("expired"), now: try c("expired").notAfter.addingTimeInterval(86_400)), "smime-expiry"), .fail) }
    func testWeak() throws { XCTAssertEqual(sev(try run("weak"), "smime-key"), .fail) }
    func testNoAddress() throws { XCTAssertEqual(sev(try run("noaddr"), "smime-address"), .fail) }
}
