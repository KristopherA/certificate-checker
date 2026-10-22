import XCTest

final class RadiusTests: XCTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }

    func testGoodServerCertificate() {
        let r = RadiusCheck.inspect([fx("ipsec-server.crt"), fx("ipsec-ca.crt"), fx("ipsec-server.key")], expectedName: "vpn.example.test")
        XCTAssertFalse(r.findings.contains { $0.severity == .fail }, "\(r.findings.filter { $0.severity == .fail }.map(\.title))")
        for id in ["rad-eku", "rad-name", "rad-key", "rad-sig-0", "rad-chain", "rad-valid", "rad-key-0"] { XCTAssertEqual(sev(r.findings, id), .pass, id) }
        XCTAssertTrue(r.findings.allSatisfy { $0.topic == .radius && !$0.kind.isEmpty })
    }
    func testBadServerCertificate() {
        let f = RadiusCheck.inspect([fx("ipsec-bad.crt"), fx("ipsec-ca.crt")], expectedName: "radius.example.test").findings
        for id in ["rad-eku", "rad-name", "rad-key", "rad-sig-0"] { XCTAssertEqual(sev(f, id), .fail, id) }
        XCTAssertEqual(sev(f, "rad-lifetime"), .warning)
    }
    func testCommonNameOnlyIsInfo() {
        XCTAssertEqual(sev(RadiusCheck.inspect([fx("ipsec-bad.crt")], expectedName: "bad.example.test").findings, "rad-name"), .info)
    }
    func testChainCases() {
        XCTAssertEqual(sev(RadiusCheck.inspect([fx("ipsec-server.crt")], expectedName: nil).findings, "rad-chain"), .warning)
        let exp = RadiusCheck.inspect([fx("ipsec-underexp.crt"), fx("ipsec-intexp.crt"), fx("ipsec-ca.crt")], expectedName: nil).findings
        XCTAssertEqual(sev(exp, "rad-chain"), .fail); XCTAssertEqual(sev(exp, "rad-caexp-1"), .fail)
        XCTAssertEqual(sev(RadiusCheck.inspect([fx("ipsec-old.crt"), fx("ipsec-ca.crt")], expectedName: nil).findings, "rad-lifetime"), nil, "pre-2019 cert: no 825-day warning")
        let key = RadiusCheck.inspect([fx("ipsec-server.crt"), fx("ipsec-other.key")], expectedName: nil).findings
        XCTAssertEqual(sev(key, "rad-key-0"), .fail)
    }
    func testProbeConfigAndArgumentsContainNoSecret() {
        for m in EAPMethod.allCases {
            let c = RadiusProbe.config(m)
            XCTAssertTrue(c.contains("eap=\(m.rawValue)")); XCTAssertTrue(c.contains("anonymous_identity=\"anonymous\"")); XCTAssertTrue(c.contains("\tidentity=\"certchecker-probe@invalid.example\""))
            XCTAssertFalse(c.contains("ca_cert")); XCTAssertFalse(c.contains("SYNTH-secret"))
        }
        XCTAssertTrue(RadiusProbe.config(.peap).contains("auth=MSCHAPV2")); XCTAssertTrue(RadiusProbe.config(.ttls).contains("auth=PAP"))
        let a = RadiusProbe.arguments(config: "/t/c", address: "192.0.2.5", port: 1812, secret: "SYNTH-secret", certOut: "/t/o.pem")
        XCTAssertEqual(a.filter { $0 == "SYNTH-secret" }.count, 1); XCTAssertEqual(a[a.firstIndex(of: "-s")! + 1], "SYNTH-secret")
        XCTAssertEqual(a[a.firstIndex(of: "-r")! + 1], "0"); XCTAssertEqual(a[a.firstIndex(of: "-o")! + 1], "/t/o.pem")
    }
    func testRedaction() {
        let out = "RADIUS secret: SYNTH-secret\nEAP: Received EAP-Request id=1 SYNTH-secret\nrandom noise\nCTRL-EVENT-EAP-FAILURE\n"
        let l = RadiusProbe.redact(out, secret: "SYNTH-secret")
        XCTAssertFalse(l.joined().contains("SYNTH-secret")); XCTAssertFalse(l.joined().lowercased().contains("secret"))
        XCTAssertEqual(l.count, 2); XCTAssertFalse(l.joined().contains("noise"))
    }
    func testMissingToolSkipsWithInstallGuidance() {
        let r = RadiusProbe.run(host: "192.0.2.1", expectedName: nil, secret: "x", tool: nil)
        XCTAssertTrue(r.skipped); XCTAssertEqual(r.findings.first?.kind, "install"); XCTAssertEqual(r.findings.first?.severity, .info)
        let g = RadiusAdvisor.guidance(for: r.findings[0], platform: .macOS)
        XCTAssertEqual(g.count, 1); XCTAssertTrue(g[0].commands.contains { $0.contains("CONFIG_EAPOL_TEST=y") }); XCTAssertTrue(g[0].commands.contains("brew search eapol_test"))
    }
    func testInputValidation() {
        let tool = URL(fileURLWithPath: "/usr/bin/true")
        XCTAssertEqual(RadiusProbe.run(host: "a b;rm", expectedName: nil, secret: "s", tool: tool).findings.first?.id, "rad-probe-input")
        XCTAssertEqual(RadiusProbe.run(host: "192.0.2.1", port: 0, expectedName: nil, secret: "s", tool: tool).findings.first?.id, "rad-probe-input")
        XCTAssertEqual(RadiusProbe.run(host: "192.0.2.1", expectedName: nil, secret: "", tool: tool).findings.first?.id, "rad-probe-input")
    }
    func testRedactionDropsMPPEHexdumpAndMidLineSecret() {
        let out = """
        EAP: MPPE keys OK
        MPPE_SEND_KEY - hexdump(len=32): 01 02 03
        EAP-TLS: Derived key - hexdump(len=64): aa bb
        RADIUS: shared key xSYNTH-mid-42y appears here
        RADIUS: Received Access-Challenge
        CTRL-EVENT-EAP-SUCCESS
        """
        let l = RadiusProbe.redact(out, secret: "SYNTH-mid-42")
        let j = l.joined(separator: "\n")
        XCTAssertFalse(j.contains("MPPE")); XCTAssertFalse(j.lowercased().contains("hexdump")); XCTAssertFalse(j.contains("SYNTH-mid-42"))
        XCTAssertTrue(j.contains("Access-Challenge")); XCTAssertTrue(j.contains("CTRL-EVENT-EAP-SUCCESS"))
    }
    func testFakeToolIgnoringSIGTERMIsKilled() throws {
        let tool = try fakeTool("trap '' TERM; echo 'EAP: started'; while :; do sleep 1; done\n")
        let start = Date()
        let r = RadiusProbe.run(host: "127.0.0.1", expectedName: nil, secret: "SYNTH-term", tool: tool, timeout: 1, grace: 0)
        XCTAssertLessThan(Date().timeIntervalSince(start), 10)
        let t = r.findings.first { $0.id == "rad-probe-timeout" }
        XCTAssertEqual(t?.severity, .fail); XCTAssertTrue(t?.title.contains("SIGKILL") ?? false, t?.title ?? "no timeout finding")
        XCTAssertFalse((r.transcript + r.findings.map { $0.title + $0.detail }).joined().contains("SYNTH-term"))
    }
    /// A fake eapol_test (no network) that writes a chain to -o, echoes its arguments, and fails like a reject.
    func fakeTool(_ body: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fake-eapol-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let u = dir.appendingPathComponent("eapol_test")
        try ("#!/bin/sh\n" + body).write(to: u, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: u.path)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return u
    }
    func testFakeProbeCapturesChainAndNeverLeaksSecret() throws {
        let chain = fx("ipsec-server.crt").path, ca = fx("ipsec-ca.crt").path
        let tool = try fakeTool("""
        out=""; conf=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; -c) conf="$2"; shift;; esac; shift; done
        cat '\(chain)' '\(ca)' > "$out"
        echo "EAP: args $*"; echo "EAP: config $(grep -c anonymous "$conf") anonymous lines"; echo "RADIUS: Access-Reject"; echo "FAILURE"; exit 255
        """)
        let r = RadiusProbe.run(host: "127.0.0.1", expectedName: "vpn.example.test", secret: "SYNTH-secret-123", tool: tool)
        XCTAssertEqual(r.chain.count, 2)
        XCTAssertEqual(sev(r.findings, "rad-probe-ok"), .info); XCTAssertEqual(sev(r.findings, "rad-name"), .pass); XCTAssertEqual(sev(r.findings, "rad-chain"), .pass)
        XCTAssertTrue(r.transcript.contains { $0.contains("Access-Reject") })
        XCTAssertFalse((r.transcript + r.findings.map { $0.title + $0.detail }).joined().contains("SYNTH-secret-123"))
    }
    func testFakeProbeNoCertificateAndTimeout() throws {
        let none = RadiusProbe.run(host: "127.0.0.1", expectedName: nil, secret: "s3", tool: try fakeTool("echo 'EAP: No response from server'; exit 1\n"))
        XCTAssertEqual(sev(none.findings, "rad-probe-nocert"), .fail)
    }
    func testGuidanceOrderAndKB() {
        let f = Finding("x", .fail, .radius, "t", kind: "reissue")
        XCTAssertEqual(RadiusAdvisor.guidance(for: f, platform: .windowsAD).first?.title, "Windows NPS")
        XCTAssertEqual(RadiusAdvisor.guidance(for: f, platform: .pfSense).first?.title, "pfSense FreeRADIUS package")
        XCTAssertEqual(RadiusAdvisor.guidance(for: f, platform: .generic).first?.title, "FreeRADIUS on Linux")
        XCTAssertTrue(RadiusAdvisor.guidance(for: f, platform: .pfSense)[0].steps.joined().contains("Diagnostics › Command Prompt"))
        XCTAssertTrue(RadiusAdvisor.docs.contains(KB.radiusGuide))
    }
}
