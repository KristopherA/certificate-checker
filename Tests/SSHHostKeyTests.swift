import XCTest
/// SSH host keys vs known_hosts (0.9.0). SYNTHETIC-ssh-* fixtures from make-ssh-fixtures.sh; offline, no connection.
final class SSHHostKeyTests: PinnedTestCase {
    func txt(_ n: String) throws -> String { String(decoding: try Data(contentsOf: CertificateCheckerTests.fixtures.appendingPathComponent("SYNTHETIC-ssh-\(n)")), as: UTF8.self) }
    func keys(_ n: String) throws -> [SSHKey] { SSHHostKeys.parseHostKeys(try txt(n)) }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }

    func testParseAndBits() throws {
        let k = try keys("host.pub"); XCTAssertEqual(k.map(\.type), ["ssh-ed25519", "ssh-rsa"])
        XCTAssertEqual(k[1].rsaBits, 3072); XCTAssertEqual(try keys("rsa1024.pub").first?.rsaBits, 1024)
        XCTAssertTrue(k[0].fingerprint.hasPrefix("SHA256:"))
        XCTAssertTrue(SSHHostKeys.parseHostKeys("ssh-rsa !!!notbase64\nssh-ed25519 AAAAC3NzaC1yc2E=").isEmpty, "type mismatch or junk is ignored")
    }
    func testMatchPlainAndHashed() throws {
        for kh in ["known_hosts", "known_hosts-hashed"] {
            let f = SSHHostKeys.inspect(hostKeys: try keys("host.pub"), knownHosts: SSHHostKeys.parseKnownHosts(try txt(kh)), host: "SSH.example.test")
            XCTAssertEqual(sev(f, "ssh-known"), .pass, kh); XCTAssertFalse(f.contains { $0.severity == .fail }, kh)
        }
    }
    func testNonStandardPort() throws {
        let f = SSHHostKeys.inspect(hostKeys: try keys("rsa3072.pub"), knownHosts: SSHHostKeys.parseKnownHosts(try txt("known_hosts-hashed")), host: "ssh.example.test", port: 2222)
        XCTAssertEqual(sev(f, "ssh-known"), .pass)
    }
    func testRotatedKeyMismatch() throws {
        let f = SSHHostKeys.inspect(hostKeys: try keys("ed-rotated.pub"), knownHosts: SSHHostKeys.parseKnownHosts(try txt("known_hosts")), host: "ssh.example.test")
        XCTAssertEqual(sev(f, "ssh-mismatch-ssh-ed25519"), .fail)
    }
    func testRevokedAndWeak() throws {
        let f = SSHHostKeys.inspect(hostKeys: try keys("rsa1024.pub"), knownHosts: SSHHostKeys.parseKnownHosts(try txt("known_hosts")), host: "ssh.example.test")
        XCTAssertEqual(sev(f, "ssh-revoked-ssh-rsa"), .fail); XCTAssertEqual(sev(f, "ssh-alg-ssh-rsa"), .fail)
    }
    func testUnknownHostAndWildcardAndNegation() throws {
        let kh = SSHHostKeys.parseKnownHosts(try txt("known_hosts")), k = try keys("ed.pub")
        XCTAssertEqual(sev(SSHHostKeys.inspect(hostKeys: k, knownHosts: kh, host: "other.example.test"), "ssh-known"), .warning)
        XCTAssertEqual(sev(SSHHostKeys.inspect(hostKeys: k, knownHosts: kh, host: "a.wild.example.test"), "ssh-known"), .pass)
        let neg = SSHHostKeys.parseKnownHosts("*.example.test,!bad.example.test " + (try txt("ed.pub")).split(separator: " ").prefix(2).joined(separator: " "))
        XCTAssertEqual(sev(SSHHostKeys.inspect(hostKeys: k, knownHosts: neg, host: "bad.example.test"), "ssh-known"), .warning)
    }
    func testDSA() {
        func s(_ b: [UInt8]) -> [UInt8] { withUnsafeBytes(of: UInt32(b.count).bigEndian, Array.init) + b }
        let blob = s(Array("ssh-dss".utf8)) + s([1]) + s([1]) + s([1]) + s([1])
        let k = SSHHostKeys.parseHostKeys("ssh-dss " + Data(blob).base64EncodedString())
        XCTAssertEqual(sev(SSHHostKeys.inspect(hostKeys: k, knownHosts: nil, host: nil), "ssh-alg-ssh-dss"), .fail)
    }
}

final class SSHHostKeyReviewTests: PinnedTestCase {
    func testGlobIsLinearAndNonRecursive() {
        let pat = String(repeating: "*a", count: 2_000) + "*b", s = String(repeating: "a", count: 5_000)
        let t = Date(); XCTAssertFalse(SSHHostKeys.glob(pat, s)); XCTAssertLessThan(Date().timeIntervalSince(t), 5)
        XCTAssertTrue(SSHHostKeys.glob("*.example.test", "a.b.example.test")); XCTAssertTrue(SSHHostKeys.glob("h?st", "host"))
        XCTAssertFalse(SSHHostKeys.glob("*.example.test", "example.test"))
    }
    func testRevokedAndPlainDoesNotPass() throws {
        let line = String(decoding: try Data(contentsOf: CertificateCheckerTests.fixtures.appendingPathComponent("SYNTHETIC-ssh-ed.pub")), as: UTF8.self).split(separator: " ").prefix(2).joined(separator: " ")
        let kh = SSHHostKeys.parseKnownHosts("h.example.test\t\(line)\n@revoked h.example.test \(line)\n")
        let f = SSHHostKeys.inspect(hostKeys: SSHHostKeys.parseHostKeys(line), knownHosts: kh, host: "h.example.test")
        XCTAssertEqual(f.first { $0.id == "ssh-revoked-ssh-ed25519" }?.severity, .fail)
        XCTAssertNotEqual(f.first { $0.id == "ssh-known" }?.severity, .pass)
    }
}
