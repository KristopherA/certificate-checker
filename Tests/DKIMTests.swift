import XCTest
/// DKIM (0.9.0). SYNTHETIC-dkim-* fixtures from make-dkim-fixtures.sh; offline, no DNS.
final class DKIMTests: PinnedTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent("SYNTHETIC-dkim-\(n)") }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }

    func testRSA2048Matches() throws {
        let f = DKIM.inspect(try DKIM.recordFile(fx("2048.txt")), privateKey: try DKIM.privateKeyPublicHalf(fx("2048.key")))
        XCTAssertEqual(sev(f, "dkim-key"), .pass); XCTAssertEqual(sev(f, "dkim-match"), .pass); XCTAssertFalse(f.contains { $0.severity == .fail })
    }
    func testMismatch() throws {
        XCTAssertEqual(sev(DKIM.inspect(try DKIM.recordFile(fx("2048.txt")), privateKey: try DKIM.privateKeyPublicHalf(fx("1024.key"))), "dkim-match"), .fail)
    }
    func testZoneFile1024Sha1Testing() throws {
        let r = try DKIM.recordFile(fx("1024.txt")), f = DKIM.inspect(r, privateKey: try DKIM.privateKeyPublicHalf(fx("1024.key")))
        XCTAssertEqual(sev(f, "dkim-key"), .warning); XCTAssertEqual(sev(f, "dkim-hash"), .warning)
        XCTAssertEqual(sev(f, "dkim-testing"), .warning); XCTAssertEqual(sev(f, "dkim-match"), .pass)
    }
    func testEd25519() throws {
        let f = DKIM.inspect(try DKIM.recordFile(fx("ed.txt")), privateKey: try DKIM.privateKeyPublicHalf(fx("ed.key")))
        XCTAssertEqual(sev(f, "dkim-match"), .pass)
    }
    func testRevoked() throws { XCTAssertEqual(sev(DKIM.inspect(try DKIM.recordFile(fx("revoked.txt"))), "dkim-revoked"), .warning) }
    func testMalformed() {
        XCTAssertThrowsError(try DKIM.parse("v=DKIM1; k=rsa"))
        XCTAssertThrowsError(try DKIM.parse("v=DKIM1; p=!!!"))
        XCTAssertThrowsError(try DKIM.parse("p=AA; p=BB"))
        XCTAssertEqual(sev(DKIM.inspect(try DKIM.parse("v=DKIM2; p=")), "dkim-version"), .fail)
        XCTAssertEqual(sev(DKIM.inspect(try DKIM.parse("k=dsa; p=AAAA")), "dkim-type"), .fail)
    }
}
