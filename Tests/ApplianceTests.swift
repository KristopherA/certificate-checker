import XCTest

/// Synology DSM / Proxmox VE / Proxmox Backup Server (0.6.0). SYNTHETIC-* fixtures; live test uses the loopback fake server only.
final class ApplianceTests: XCTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }
    func chain(_ n: String) throws -> [Certificate] { try PEM.blocks(String(decoding: try Data(contentsOf: fx(n)), as: UTF8.self)).map { try Certificate(der: $0.der) } }
    let untrusted = [Finding("trust", .fail, .trust, "Not trusted")]

    func testServiceDefaults() {
        XCTAssertEqual(Service.synologyDSM.defaultPort, 5001); XCTAssertEqual(Service.proxmoxVE.defaultPort, 8006); XCTAssertEqual(Service.proxmoxBackup.defaultPort, 8007)
        XCTAssertEqual(Service.proxmoxBackup.defaultPlatform, .proxmoxBackup); XCTAssertEqual(Service.rdp.defaultPlatform, .windowsRDP)
        for s in [Service.synologyDSM, .proxmoxVE, .proxmoxBackup] { XCTAssertTrue(s.isAppliance); XCTAssertFalse(s.usesUpgrade); XCTAssertFalse(s.isRemoteAdmin) }
        XCTAssertFalse(Service.https.isAppliance)
    }
    func testFingerprintNormalize() {
        let hex = String(repeating: "ab", count: 32), colon = (0..<32).map { _ in "AB" }.joined(separator: ":")
        XCTAssertEqual(FingerprintPin.normalize(colon.lowercased()), colon)
        XCTAssertEqual(FingerprintPin.normalize("  \(colon)\n"), colon)
        XCTAssertEqual(FingerprintPin.normalize(hex), colon)
        XCTAssertNil(FingerprintPin.normalize("")); XCTAssertNil(FingerprintPin.normalize("AB:CD"))
        XCTAssertNil(FingerprintPin.normalize(String(colon.dropLast(3))))          // 31 bytes (SHA-1 length is also rejected)
        XCTAssertNil(FingerprintPin.normalize(colon.replacingOccurrences(of: "AB", with: "ZZ")))
        XCTAssertNil(FingerprintPin.normalize(colon + ":"))
        XCTAssertNil(FingerprintPin.normalize(String(repeating: "a", count: 63)))
    }
    func testPBSPinMatchMismatchInvalidMissing() throws {
        let c = try chain("SYNTHETIC-pbs-selfsigned.pem"); XCTAssertEqual(c.count, 1)
        var t = Target(name: "", host: "pbs.example.test", service: .proxmoxBackup)
        XCTAssertTrue(Appliance.isPBSDefault(c[0]))
        t.fingerprintPin = c[0].sha256.lowercased()
        var f = Appliance.adjust(untrusted, chain: c, target: t)
        XCTAssertEqual(sev(f, "pbs-pin"), .pass); XCTAssertEqual(sev(f, "trust"), .info, "matching pin explains the self-signed trust failure")
        XCTAssertEqual(sev(f, "pbs-selfsigned"), .info); XCTAssertEqual(sev(f, "appl-fp"), .info)
        t.fingerprintPin = c[0].sha256.replacingOccurrences(of: ":", with: "")
        XCTAssertEqual(sev(Appliance.adjust(untrusted, chain: c, target: t), "pbs-pin"), .pass, "plain hex accepted")
        t.fingerprintPin = String(repeating: "00:", count: 31) + "00"
        f = Appliance.adjust(untrusted, chain: c, target: t)
        XCTAssertEqual(sev(f, "pbs-pin"), .fail); XCTAssertEqual(sev(f, "trust"), .fail, "mismatch must not downgrade trust")
        XCTAssertTrue(f.first { $0.id == "pbs-pin" }!.detail.contains(c[0].sha256))
        t.fingerprintPin = "nope"
        XCTAssertEqual(sev(Appliance.adjust(untrusted, chain: c, target: t), "pbs-pin"), .fail)
        t.fingerprintPin = nil
        f = Appliance.adjust(untrusted, chain: c, target: t)
        XCTAssertEqual(sev(f, "pbs-pin"), .warning); XCTAssertEqual(sev(f, "trust"), .warning)
        // Expired: never downgraded, even with a matching pin.
        t.fingerprintPin = c[0].sha256
        XCTAssertEqual(sev(Appliance.adjust(untrusted, chain: c, target: t, now: c[0].notAfter.addingTimeInterval(86_400)), "trust"), .fail)
    }
    func testDSMDefault() throws {
        let c = try chain("SYNTHETIC-dsm-default.pem"); XCTAssertEqual(c.count, 2)
        XCTAssertTrue(Appliance.isSynologyDefault(c[0]))
        let t = Target(name: "", host: "nas.example.test", service: .synologyDSM)
        let f = Appliance.adjust(untrusted, chain: c, target: t)
        XCTAssertEqual(sev(f, "dsm-default"), .warning); XCTAssertEqual(sev(f, "trust"), .warning)
        XCTAssertNil(sev(f, "pbs-pin"))
        XCTAssertFalse(Appliance.isSynologyDefault(try chain("SYNTHETIC-pbs-selfsigned.pem")[0]))
    }
    func testPVEDefault() throws {
        let c = try chain("SYNTHETIC-pve-default.pem")
        XCTAssertTrue(Appliance.isPVEDefault(c[0])); XCTAssertFalse(Appliance.isPVEDefault(try chain("SYNTHETIC-dsm-default.pem")[0]))
        let t = Target(name: "", host: "pve1.example.test", service: .proxmoxVE)
        let f = Appliance.adjust(untrusted, chain: c, target: t)
        XCTAssertEqual(sev(f, "pve-default"), .warning); XCTAssertEqual(sev(f, "trust"), .warning)
        // A chain whose signatures do not verify (leaf with the wrong CA) is not downgraded.
        let wrong = [c[0], try chain("SYNTHETIC-dsm-default.pem")[1]]
        XCTAssertEqual(sev(Appliance.adjust(untrusted, chain: wrong, target: t), "trust"), .fail)
    }
    func testNonApplianceUnchanged() throws {
        let c = try chain("SYNTHETIC-pbs-selfsigned.pem")
        let f = Appliance.adjust(untrusted, chain: c, target: Target(name: "", host: "h.example.test", service: .https))
        XCTAssertEqual(f.count, 1); XCTAssertEqual(sev(f, "trust"), .fail)
    }
    func testFileAnalysisCoversExpiryAndSAN() throws {
        let c = try chain("SYNTHETIC-pve-default.pem")
        let f = Analysis.evaluate(certificates: c, hostname: "other.example.test", purpose: .tlsServer)
        XCTAssertEqual(sev(f, "host"), .fail, "SAN mismatch is still reported for appliance certificates")
        XCTAssertEqual(sev(Analysis.evaluate(certificates: c, hostname: "pve1.example.test", purpose: .tlsServer), "host"), .pass)
    }
    func testGuidanceIsProductSpecificAndCopyOnly() {
        let pve = Target(name: "", host: "pve1.example.test", service: .proxmoxVE)
        let g = Advisor.guidance(for: .expiry, platform: .generic, target: pve)
        XCTAssertTrue(g.first!.title.contains("Proxmox VE")); XCTAssertTrue(g.first!.commands.contains { $0.hasPrefix("pvenode cert set") })
        XCTAssertTrue(g.first!.commands.contains { $0.contains("pvenode acme cert order") })
        let pbs = ApplianceAdvisor.guidance(for: Finding("pbs-pin", .fail, .appliance, "x", kind: "pbs-pin"), target: Target(name: "", host: "p.example.test", service: .proxmoxBackup))
        XCTAssertTrue(pbs.first!.commands.contains { $0.hasPrefix("proxmox-backup-manager cert") })
        XCTAssertTrue(ApplianceAdvisor.guidance(for: Finding("pbs-pin", .pass, .appliance, "x", kind: "pbs-pin"), target: nil).isEmpty)
        let dsm = ApplianceAdvisor.guidance(for: Finding("dsm-default", .warning, .appliance, "x", kind: "dsm-cert"), target: nil)
        XCTAssertTrue(dsm.first!.steps.contains { $0.contains("Control Panel › Security › Certificate") })
        for c in (dsm + pbs + g).flatMap(\.commands) { XCTAssertFalse(c.contains("BEGIN"), "no key material in guidance") }
    }
    func testFormAndTargetValidation() throws {
        var f = ApplianceForm()
        XCTAssertEqual(f.port, "5001"); XCTAssertFalse(f.canRun)
        f.select(.proxmoxBackup); XCTAssertEqual(f.port, "8007"); f.fingerprint = " " + String(repeating: "AB:", count: 31) + "AB "; f.host = " pbs.example.test "
        XCTAssertTrue(f.canRun); XCTAssertEqual(f.target.platform, .proxmoxBackup); XCTAssertNotNil(f.target.fingerprintPin); XCTAssertNoThrow(try f.target.validate())
        f.select(.proxmoxVE); XCTAssertEqual(f.port, "8006"); XCTAssertNotNil(f.target.fingerprintPin, "PVE keeps the pin (0.6.1)")
        f.select(.synologyDSM); XCTAssertEqual(f.port, "5001"); XCTAssertEqual(f.fingerprint, ""); XCTAssertNil(f.target.fingerprintPin)
        var t = Target(name: "x", host: "h.example.test", service: .synologyDSM); t.fingerprintPin = String(repeating: "AB:", count: 31) + "AB"
        XCTAssertThrowsError(try t.validate(), "no pin for DSM")
        t.service = .proxmoxBackup; t.fingerprintPin = "AB:CD"; XCTAssertThrowsError(try t.validate())
        // targets.json written before 0.6.0 (no fingerprintPin key) still decodes.
        let old = #"[{"id":"7D3F0E4A-1111-4222-8333-944455556666","name":"n","host":"h.example.test","port":443,"service":"HTTPS","sni":"","expectedName":"","platform":"Generic / unknown","notes":""}]"#
        let d = try JSONDecoder().decode([Target].self, from: Data(old.utf8)); XCTAssertNil(d[0].fingerprintPin)
    }
    func testFingerprintRejectsNonASCIIHex() throws {
        let ascii = (0..<32).map { _ in "10" }.joined(separator: ":")
        XCTAssertNotNil(FingerprintPin.normalize(ascii))
        let fullwidth = ascii.replacingOccurrences(of: "1", with: "\u{FF11}").replacingOccurrences(of: "0", with: "\u{FF10}")
        XCTAssertNil(FingerprintPin.normalize(fullwidth), "fullwidth digits are malformed, not hex")
        XCTAssertNil(FingerprintPin.normalize(ascii.replacingOccurrences(of: "10", with: "\u{0661}\u{0660}")), "Arabic-Indic digits rejected")
        // Reported as malformed, not as a mismatch.
        let c = try chain("SYNTHETIC-pbs-selfsigned.pem")
        var t = Target(name: "", host: "pbs.example.test", service: .proxmoxBackup); t.fingerprintPin = fullwidth
        let f = Appliance.adjust(untrusted, chain: c, target: t).first { $0.id == "pbs-pin" }!
        XCTAssertEqual(f.severity, .fail); XCTAssertTrue(f.title.contains("not a SHA-256"), f.title)
        XCTAssertThrowsError(try t.validate())
    }
    func testLeafSHA256FormatIsUppercaseColonHex() throws {
        // Pin comparison is a plain string compare against leaf.sha256, so its format is locked here.
        for n in ["SYNTHETIC-pbs-selfsigned.pem", "SYNTHETIC-pve-default.pem", "SYNTHETIC-dsm-default.pem"] {
            let fp = try chain(n)[0].sha256
            XCTAssertEqual(fp.count, 95, n)
            XCTAssertNotNil(fp.range(of: "^[0-9A-F]{2}(:[0-9A-F]{2}){31}$", options: .regularExpression), fp)
            XCTAssertEqual(FingerprintPin.normalize(fp), fp, "already normalised")
        }
    }
    func testPVEOptionalPin() throws {
        let c = try chain("SYNTHETIC-pve-default.pem")
        var t = Target(name: "", host: "pve1.example.test", service: .proxmoxVE)
        var f = Appliance.adjust(untrusted, chain: c, target: t)
        XCTAssertNil(sev(f, "pve-pin")); XCTAssertTrue(f.first { $0.id == "pve-default" }!.detail.contains("Identity is unverified"))
        t.fingerprintPin = c[0].sha256.lowercased(); XCTAssertNoThrow(try t.validate())
        f = Appliance.adjust(untrusted, chain: c, target: t)
        XCTAssertEqual(sev(f, "pve-pin"), .pass); XCTAssertEqual(sev(f, "trust"), .info)
        XCTAssertFalse(f.first { $0.id == "pve-default" }!.detail.contains("Identity is unverified"))
        t.fingerprintPin = String(repeating: "00:", count: 31) + "00"
        f = Appliance.adjust(untrusted, chain: c, target: t)
        XCTAssertEqual(sev(f, "pve-pin"), .fail); XCTAssertEqual(sev(f, "trust"), .fail, "mismatch: no downgrade")
        XCTAssertFalse(ApplianceAdvisor.guidance(for: f.first { $0.id == "pve-pin" }!, target: t).isEmpty)
        t.fingerprintPin = "AB:CD"; XCTAssertEqual(sev(Appliance.adjust(untrusted, chain: c, target: t), "pve-pin"), .fail)
        // DSM still does not accept a pin, and its default-cert warning says identity is unverified.
        var d = Target(name: "", host: "nas.example.test", service: .synologyDSM); d.fingerprintPin = c[0].sha256
        XCTAssertThrowsError(try d.validate())
        XCTAssertTrue(Appliance.adjust(untrusted, chain: try chain("SYNTHETIC-dsm-default.pem"), target: d).first { $0.id == "dsm-default" }!.detail.contains("Identity is unverified"))
        var form = ApplianceForm(); form.select(.proxmoxVE); form.host = "pve1.example.test"; form.fingerprint = c[0].sha256
        XCTAssertEqual(form.target.fingerprintPin, c[0].sha256); form.select(.synologyDSM); XCTAssertEqual(form.fingerprint, "")
    }
    func testApplianceTrustNeverFetchesFromNetwork() {
        for s in [Service.synologyDSM, .proxmoxVE, .proxmoxBackup] { XCTAssertFalse(Probe.allowsTrustNetworkFetch(s), s.rawValue) }
        XCTAssertTrue(Probe.allowsTrustNetworkFetch(.https))
    }
    func testLoopbackPBSPin() async throws {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = [fx("tls_server.py").path, "tls", fx("SYNTHETIC-pbs-selfsigned.pem").path, fx("SYNTHETIC-pbs-selfsigned.key").path]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run(); defer { p.terminate() }
        guard let port = Int(String(decoding: out.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else { throw XCTSkip("test server did not start") }
        let leaf = try chain("SYNTHETIC-pbs-selfsigned.pem")[0]
        var t = Target(name: "pbs", host: "127.0.0.1", port: port, service: .proxmoxBackup, sni: "pbs.example.test"); t.fingerprintPin = leaf.sha256
        let r = await Probe.run(t, timeout: 10)
        XCTAssertNil(r.error, "\(r.error ?? "") \(r.transcript)")
        XCTAssertEqual(sev(r.findings, "pbs-pin"), .pass); XCTAssertEqual(sev(r.findings, "host"), .pass)
        XCTAssertEqual(r.chain.first?.sha256, leaf.sha256)
    }
}
