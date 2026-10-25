import XCTest

/// 0.10.1: a top certificate is an anchor only if its self-signature verifies (or it is pinned / user-supplied), and
/// eapol_test -o output (top-first, leaf repeated) is normalised leaf-first. SYNTHETIC-forged-* / -genuine-root fixtures.
final class Release0101Tests: PinnedTestCase {
    let now = PinnedTestCase.pinnedNow
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func chain(_ n: String) throws -> [Certificate] { try PEM.blocks(String(decoding: try Data(contentsOf: fx(n)), as: UTF8.self)).map { try Certificate(der: $0.der) } }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }
    let untrusted = [Finding("trust", .fail, .trust, "Not trusted")]

    func testForgedTopIsNotARoot() throws {
        for n in ["dsm", "pve", "radius"] {
            let c = try chain("SYNTHETIC-forged-\(n).pem"); XCTAssertEqual(c.count, 2)
            XCTAssertTrue(c[1].isSelfIssued, "the fake CA claims to be a root")
            XCTAssertFalse(ChainCheck.selfSignatureVerifies(c[1]), n)
            XCTAssertFalse(ChainCheck.verify(c, now: now).ok, "\(n): forged CA must not anchor")
            XCTAssertFalse(ChainCheck.verify([c[0]], now: now).ok, "\(n): a lone leaf must not anchor itself")
            XCTAssertTrue(ChainCheck.verify(c, now: now, trustedTop: true).ok, "\(n): the leaf signature itself is genuine (only the top is forged)")
        }
    }
    func testGenuineSelfSignedRootStillVerifies() throws {
        let g = try chain("SYNTHETIC-genuine-root.pem")
        XCTAssertTrue(ChainCheck.selfSignatureVerifies(g[1])); XCTAssertFalse(ChainCheck.selfSignatureVerifies(g[0]))
        XCTAssertTrue(ChainCheck.verify(g, now: now).ok)
        for n in ["SYNTHETIC-dsm-default.pem", "SYNTHETIC-pve-default.pem", "SYNTHETIC-pbs-selfsigned.pem", "rdp-selfsigned.pem"] {
            let c = try chain(n); XCTAssertTrue(ChainCheck.verify(c, now: now).ok, n)
        }
        XCTAssertEqual(sev(RadiusCheck.evaluate(chain: g, expectedName: "radius.example.test", now: now), "rad-chain"), .pass)
    }
    func testDSMForgedChainAndLoneLeafAreNotDowngraded() throws {
        let t = Target(name: "", host: "nas.example.test", service: .synologyDSM)
        for c in [try chain("SYNTHETIC-forged-dsm.pem"), try chain("SYNTHETIC-forged-dsm-leaf.pem")] {
            let f = Appliance.adjust(untrusted, chain: c, target: t, now: now)
            XCTAssertEqual(sev(f, "dsm-default"), .warning); XCTAssertEqual(sev(f, "trust"), .fail, "forged DSM chain (\(c.count) certs) must stay a trust failure")
        }
        XCTAssertEqual(sev(Appliance.adjust(untrusted, chain: try chain("SYNTHETIC-dsm-default.pem"), target: t, now: now), "trust"), .warning, "genuine factory CA still downgrades")
    }
    func testPVEWithoutPinForgedIsNotDowngradedButPinStillWorks() throws {
        var t = Target(name: "", host: "pve1.example.test", service: .proxmoxVE)
        for c in [try chain("SYNTHETIC-forged-pve.pem"), try chain("SYNTHETIC-forged-pve-leaf.pem")] {
            XCTAssertEqual(sev(Appliance.adjust(untrusted, chain: c, target: t, now: now), "trust"), .fail)
        }
        let leaf = try chain("SYNTHETIC-forged-pve-leaf.pem")
        t.fingerprintPin = leaf[0].sha256
        let f = Appliance.adjust(untrusted, chain: leaf, target: t, now: now)
        XCTAssertEqual(sev(f, "pve-pin"), .pass); XCTAssertEqual(sev(f, "trust"), .info, "the user's pin is the trust anchor")
    }
    func testRadiusForgedChainIsNotAPass() throws {
        let c = try chain("SYNTHETIC-forged-radius.pem")
        XCTAssertEqual(sev(RadiusCheck.evaluate(chain: c, expectedName: "radius.example.test", now: now), "rad-chain"), .fail)
        let lone = RadiusCheck.evaluate(chain: [c[0]], expectedName: "radius.example.test", now: now)
        XCTAssertEqual(sev(lone, "rad-chain"), .warning, "a lone leaf is never a pass")
    }
    func testEapolOrderIsNormalisedLeafFirst() throws {
        let g = try chain("SYNTHETIC-genuine-root.pem")
        let n = RadiusProbe.normalize([g[1], g[0], g[0]])   // eapol_test -o: top first, leaf repeated
        XCTAssertEqual(n.map(\.sha256), [g[0].sha256, g[1].sha256])
        XCTAssertEqual(RadiusProbe.normalize(g).map(\.sha256), g.map(\.sha256), "already leaf-first stays put")
    }
    func testFakeProbeTopFirstFileIsNormalisedWithoutOrderWarning() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fake-eapol-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let leafF = dir.appendingPathComponent("leaf.pem"), rootF = dir.appendingPathComponent("root.pem")
        let g = try chain("SYNTHETIC-genuine-root.pem")
        try FileCheckHelper.writePEM(g[0].der, to: leafF); try FileCheckHelper.writePEM(g[1].der, to: rootF)
        let tool = dir.appendingPathComponent("eapol_test")
        try """
        #!/bin/sh
        out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; esac; shift; done
        cat '\(rootF.path)' '\(leafF.path)' '\(leafF.path)' > "$out"; echo "RADIUS: Access-Reject"; exit 255
        """.write(to: tool, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: tool.path)
        let r = RadiusProbe.run(host: "127.0.0.1", expectedName: "radius.example.test", secret: "SYNTH-0101", tool: tool)
        XCTAssertEqual(r.chain.map(\.sha256), g.map(\.sha256))
        XCTAssertNil(sev(r.findings, "rad-order")); XCTAssertEqual(sev(r.findings, "rad-probe-ok"), .info)
        XCTAssertEqual(sev(r.findings, "rad-name"), .pass); XCTAssertEqual(sev(r.findings, "rad-chain"), .pass)
    }
}

enum FileCheckHelper {
    static func writePEM(_ der: [UInt8], to url: URL) throws {
        let b = Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        try "-----BEGIN CERTIFICATE-----\n\(b)\n-----END CERTIFICATE-----\n".write(to: url, atomically: true, encoding: .utf8)
    }
}
