import XCTest

/// 0.10.1 build 19: no MD5/SHA-1 link counts as proof of issuance (rad-bad / ipsec-bad), and IPsec trusts the top
/// of a chain only when it is one of the config's own CAs, byte-equal or same SPKI (ipsec-top-not-sent).
final class Release0101Build19Tests: PinnedTestCase {
    let now = PinnedTestCase.pinnedNow
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func certs(_ n: String) throws -> [Certificate] { try PEM.blocks(String(decoding: try Data(contentsOf: fx(n)), as: UTF8.self)).map { try Certificate(der: $0.der) } }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }

    func testSHA1LinkIsNeverProofOfIssuance() throws {
        let leaf = try certs("ipsec-bad.crt")[0], ca = try certs("ipsec-ca.crt")[0]
        XCTAssertTrue(leaf.signatureIsWeak); XCTAssertTrue(ChainCheck.selfSignatureVerifies(ca), "the CA is a genuine root")
        for trusted in [false, true] {
            let v = ChainCheck.verify([leaf, ca], now: now, trustedTop: trusted)
            XCTAssertFalse(v.ok, "a SHA-1 link must fail even with a trusted top (\(trusted))")
            XCTAssertTrue(v.message.contains("SHA-1") && v.message.contains("sha1WithRSA"), v.message)
        }
        let r = RadiusCheck.inspect([fx("ipsec-bad.crt"), fx("ipsec-ca.crt")], expectedName: "radius.example.test", now: now).findings
        XCTAssertEqual(sev(r, "rad-chain"), .fail); XCTAssertEqual(sev(r, "rad-sig-0"), .fail)
        let i = IPsecCheck.inspect([fx("ipsec-bad.crt"), fx("ipsec-ca.crt")], now: now).findings
        XCTAssertEqual(sev(i, "srv0-chain"), .fail)
    }
    func testSHA256ChainsStillVerify() throws {
        let g = try certs("SYNTHETIC-genuine-root.pem")
        XCTAssertFalse(g[0].signatureIsWeak); XCTAssertTrue(ChainCheck.verify(g, now: now).ok)
    }
    func testIPsecTrustsOnlyTheConfigsOwnCA() throws {
        let leaf = try certs("ipsec-rollleaf.crt")[0], roll = try certs("ipsec-roll.crt")[0]
        XCTAssertFalse(ChainCheck.selfSignatureVerifies(roll), "rollover CA: self-issued, signed by the old key")
        XCTAssertFalse(ChainCheck.verify([leaf, roll], now: now).ok, "strict default: not a verified root")
        XCTAssertTrue(ChainCheck.isUserSupplied(roll, in: [roll]))
        XCTAssertFalse(ChainCheck.isUserSupplied(roll, in: [leaf]))
        XCTAssertFalse(ChainCheck.isUserSupplied(roll, in: try certs("SYNTHETIC-genuine-root.pem")), "a different key is not the user's CA")
        let i = IPsecCheck.inspect([fx("ipsec-rollleaf.crt"), fx("ipsec-roll.crt")], now: now).findings
        XCTAssertEqual(sev(i, "srv0-chain"), .pass, "the rollover CA is in the config, so it anchors")
        XCTAssertEqual(sev(i, "srv0-chain-top"), .warning, "and clients still need its root")
        // The same chain on its own (no config CA) falls back to the strict default.
        XCTAssertEqual(sev(RadiusCheck.evaluate(chain: [leaf, roll], expectedName: nil, now: now), "rad-chain"), .fail)
    }
    func testForgedTopOutsideTheConfigDoesNotAnchor() throws {
        let c = try certs("SYNTHETIC-forged-radius.pem")
        XCTAssertFalse(ChainCheck.isUserSupplied(c[1], in: try certs("SYNTHETIC-genuine-root.pem")))
        XCTAssertFalse(ChainCheck.verify(c, now: now, trustedTop: ChainCheck.isUserSupplied(c[1], in: [])).ok)
    }
}
