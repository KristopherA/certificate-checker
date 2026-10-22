import XCTest

/// RDP / RD Gateway / WinRM. Live tests use the loopback fake server (tls_server.py) only.
final class RemoteTests: XCTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }

    // MARK: Wire format
    func testConnectionRequestBytes() {
        let r = RDP.connectionRequest()
        XCTAssertEqual(r.count, 19)
        XCTAssertEqual(r, [0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00])
        XCTAssertFalse(String(decoding: r, as: UTF8.self).contains("mstshash"), "no cookie / user name is sent")
    }
    func testParseConfirm() throws {
        let cc: [UInt8] = [0x0E, 0xD0, 0, 0, 0x12, 0x34, 0]
        XCTAssertEqual(try RDP.parseConfirm(cc + [0x02, 0x1F, 0x08, 0x00, 0x02, 0, 0, 0]), .selected(2, flags: 0x1F))
        XCTAssertEqual(try RDP.parseConfirm(cc + [0x02, 0x00, 0x08, 0x00, 0x01, 0, 0, 0]), .selected(1, flags: 0))
        XCTAssertEqual(try RDP.parseConfirm(cc + [0x03, 0x00, 0x08, 0x00, 0x02, 0, 0, 0]), .failure(2))
        XCTAssertEqual(try RDP.parseConfirm([0x06, 0xD0, 0, 0, 0x12, 0x34, 0]), .legacy)
        XCTAssertThrowsError(try RDP.parseConfirm([0x06, 0x80, 0, 0, 0, 0, 0]))           // disconnect
        XCTAssertThrowsError(try RDP.parseConfirm([0x0E, 0xD0, 0, 0]))                     // truncated
        XCTAssertThrowsError(try RDP.parseConfirm(cc + [0x09, 0x00, 0x08, 0x00, 0, 0, 0, 0])) // unknown type
        XCTAssertThrowsError(try RDP.parseConfirm(cc + [0x02, 0x00, 0x07, 0x00, 0, 0, 0, 0])) // bad length
        XCTAssertEqual(try RDP.tpktLength([3, 0, 0, 0x13]), 15)
        XCTAssertThrowsError(try RDP.tpktLength(Array("HTTP".utf8)))
        XCTAssertThrowsError(try RDP.tpktLength([3, 0, 0xFF, 0xFF]))
    }
    func testNegotiationFindingsAndFailureNames() {
        XCTAssertEqual(RDP.findings(.selected(2, flags: 0)).first?.severity, .pass)
        XCTAssertEqual(RDP.findings(.selected(8, flags: 0)).first?.severity, .fail)  // HYBRID_EX was not requested (0.5.1)
        XCTAssertEqual(RDP.findings(.selected(1, flags: 0)).first?.id, "rdp-nla")
        XCTAssertEqual(RDP.findings(.selected(1, flags: 0)).first?.severity, .warning)
        XCTAssertEqual(RDP.findings(.selected(0, flags: 0)).first?.severity, .fail)
        XCTAssertEqual(RDP.findings(.legacy).first?.severity, .fail)
        for (c, n) in [(1, "SSL_REQUIRED_BY_SERVER"), (2, "SSL_NOT_ALLOWED_BY_SERVER"), (3, "SSL_CERT_NOT_ON_SERVER"), (4, "INCONSISTENT_FLAGS"), (5, "HYBRID_REQUIRED_BY_SERVER"), (6, "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER")] {
            XCTAssertEqual(RDP.failureName(UInt32(c)).name, n); XCTAssertTrue(RDP.findings(.failure(UInt32(c))).first!.title.contains(n))
        }
        XCTAssertTrue(RDP.startsTLS(.selected(1, flags: 0))); XCTAssertTrue(RDP.startsTLS(.selected(2, flags: 0))); XCTAssertFalse(RDP.startsTLS(.selected(0, flags: 0)))
        XCTAssertFalse(RDP.startsTLS(.selected(4, flags: 0))); XCTAssertFalse(RDP.startsTLS(.failure(2))); XCTAssertFalse(RDP.startsTLS(.legacy))
    }

    // MARK: Loopback fake server
    func server(_ mode: String, chain: String = "fullchain.pem", key: String = "leaf.key") throws -> (Process, Int) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = [fx("tls_server.py").path, mode, fx(chain).path, fx(key).path]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run()
        guard let port = Int(String(decoding: out.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else { p.terminate(); throw XCTSkip("test server did not start") }
        return (p, port)
    }
    func rdp(_ mode: String, chain: String = "fullchain.pem", key: String = "leaf.key", sni: String = "test.example.internal", service: Service = .rdp) async throws -> ProbeResult {
        let (p, port) = try server(mode, chain: chain, key: key); defer { p.terminate() }
        return await Probe.run(Target(name: mode, host: "127.0.0.1", port: port, service: service, sni: sni), timeout: 10)
    }
    func testRDPHybridThenTLS() async throws {
        let r = try await rdp("rdp-hybrid")
        XCTAssertNil(r.error, "\(r.error ?? "") \(r.transcript)")
        XCTAssertEqual(r.chain.count, 2); XCTAssertEqual(sev(r.findings, "rdp-neg"), .pass)
        XCTAssertEqual(sev(r.findings, "host"), .pass); XCTAssertEqual(sev(r.findings, "eku"), .pass)
        XCTAssertNotNil(r.findings.first { $0.id == "remote-thumb" })
        XCTAssertTrue(r.transcript.contains { $0.contains("CredSSP") })
    }
    func testRDPSSLWithoutNLAWarns() async throws {
        let r = try await rdp("rdp-ssl")
        XCTAssertNil(r.error); XCTAssertEqual(sev(r.findings, "rdp-nla"), .warning); XCTAssertEqual(r.chain.count, 2)
    }
    func testRDPRefusals() async throws {
        for (mode, text) in [("rdp-fail2", "SSL_NOT_ALLOWED_BY_SERVER"), ("rdp-fail3", "SSL_CERT_NOT_ON_SERVER"), ("rdp-fail5", "HYBRID_REQUIRED_BY_SERVER"),
                             ("rdp-rdpsec", "Standard RDP Security"), ("rdp-legacy", "did not negotiate")] {
            let r = try await rdp(mode)
            XCTAssertNotNil(r.error, mode); XCTAssertTrue(r.chain.isEmpty, mode)
            XCTAssertEqual(r.findings.count, 1, "\(mode): \(r.findings.map(\.id))")
            XCTAssertEqual(r.findings.first?.id, "rdp-neg", mode); XCTAssertEqual(r.findings.first?.severity, .fail, mode)
            XCTAssertTrue(r.findings.first!.title.contains(text), "\(mode): \(r.findings.first!.title)")
        }
    }
    func testRDPNotRDPOrMalformed() async throws {
        for mode in ["rdp-http", "rdp-biglen", "rdp-disconnect"] {
            let r = try await rdp(mode)
            XCTAssertNotNil(r.error, mode); XCTAssertEqual(r.findings.first?.topic, .startTLS, mode); XCTAssertTrue(r.chain.isEmpty, mode)
        }
        let inj = try await rdp("rdp-inject")
        XCTAssertTrue(inj.error?.contains("unexpected bytes") == true, inj.error ?? "no error")
    }
    func testRDPRemoteDesktopAuthEKUOnly() async throws {
        let r = try await rdp("rdp-hybrid", chain: "rdp-rda.pem", key: "rdp-rda.key", sni: "rdp.example.test")
        XCTAssertNil(r.error)
        XCTAssertEqual(sev(r.findings, "eku"), .pass, "\(r.findings.filter { $0.id == "eku" }.map(\.detail))")
        XCTAssertTrue(r.findings.first { $0.id == "trust" }!.detail.contains("Remote Desktop Authentication"))
        // The same certificate fails as a generic HTTPS / WinRM server.
        let w = try await rdp("tls", chain: "rdp-rda.pem", key: "rdp-rda.key", sni: "rdp.example.test", service: .winrmHTTPS)
        XCTAssertEqual(sev(w.findings, "eku"), .fail)
    }
    func testRDPClientAuthOnlyFails() async throws {
        let r = try await rdp("rdp-hybrid", chain: "rdp-clientonly.pem", key: "rdp-clientonly.key", sni: "rdp.example.test")
        XCTAssertEqual(sev(r.findings, "eku"), .fail)
    }
    func testRDPDefaultSelfSignedDetected() async throws {
        let r = try await rdp("rdp-hybrid", chain: "rdp-selfsigned.pem", key: "rdp-selfsigned.key", sni: "host1.example.test")
        XCTAssertNil(r.error)
        XCTAssertEqual(sev(r.findings, "rdp-selfsigned"), .warning)
        XCTAssertEqual(sev(r.findings, "trust"), .warning, "self-signed RDP trust is downgraded to a warning")
        XCTAssertEqual(sev(r.findings, "host"), .warning, "CN-only match")
    }
    func testRDGatewayAndWinRMHTTPS() async throws {
        let g = try await rdp("tls", service: .rdGateway)
        XCTAssertNil(g.error); XCTAssertEqual(sev(g.findings, "host"), .pass); XCTAssertNil(g.findings.first { $0.id == "rdg-selfsigned" })
        let gs = try await rdp("tls", chain: "rdp-selfsigned.pem", key: "rdp-selfsigned.key", sni: "host1.example.test", service: .rdGateway)
        XCTAssertEqual(sev(gs.findings, "rdg-selfsigned"), .fail)
        let w = try await rdp("tls", service: .winrmHTTPS)
        XCTAssertNil(w.error); XCTAssertEqual(sev(w.findings, "eku"), .pass); XCTAssertNil(w.findings.first { $0.id == "winrm-cn" })
        let wm = try await rdp("tls", sni: "localhost", service: .winrmHTTPS)
        XCTAssertEqual(sev(wm.findings, "winrm-cn"), .warning)
        XCTAssertEqual(WorkbenchHandoff.url(for: Target(name: "", host: "gw.example.test", service: .rdGateway)), "https://gw.example.test")
        XCTAssertNil(WorkbenchHandoff.url(for: Target(name: "", host: "h", service: .rdp)))
    }

    // MARK: WinRM HTTP 5985 (explicit only)
    func testWinRMHTTPParsingAndFindings() {
        let r = WinRMHTTP.parse(["HTTP/1.1 401 ", "WWW-Authenticate: Negotiate", "WWW-Authenticate: Basic realm=\"WSMAN\"", "Server: Microsoft-HTTPAPI/2.0"])
        XCTAssertEqual(r, WinRMHTTP.Response(status: 401, schemes: ["Negotiate", "Basic"], server: "Microsoft-HTTPAPI/2.0"))
        XCTAssertEqual(WinRMHTTP.findings(r, port: 5985).first?.severity, .fail)
        XCTAssertEqual(WinRMHTTP.findings(WinRMHTTP.Response(status: 401, schemes: ["Negotiate"], server: nil), port: 5985).first?.severity, .warning)
        XCTAssertEqual(WinRMHTTP.findings(WinRMHTTP.Response(status: 404, schemes: [], server: nil), port: 5985).first?.severity, .info)
        XCTAssertEqual(WinRMHTTP.findings(nil, port: 5985, error: "refused").first?.severity, .info)
        XCTAssertNil(WinRMHTTP.parse(["SSH-2.0-OpenSSH"]))
        let req = WinRMHTTP.request(host: "h.example.test", port: 5985)
        XCTAssertTrue(req.hasPrefix("POST /wsman HTTP/1.1\r\n")); XCTAssertFalse(req.lowercased().contains("authorization"))
    }
    func testWinRMHTTPLoopback() async throws {
        for (mode, s) in [("winrm-http", Severity.warning), ("winrm-http-basic", .fail), ("winrm-http-404", .info)] {
            let (p, port) = try server(mode); defer { p.terminate() }
            let r = await WinRMHTTP.check(host: "127.0.0.1", port: port, timeout: 5)
            XCTAssertEqual(r.findings.first?.severity, s, "\(mode) \(r.findings.map(\.title)) \(r.transcript)")
        }
        let (p, port) = try server("winrm-http"); p.terminate(); p.waitUntilExit()
        let closed = await WinRMHTTP.check(host: "127.0.0.1", port: port, timeout: 3)
        XCTAssertEqual(closed.findings.first?.severity, .info)
    }

    // MARK: 0.5.1 follow-ups
    func testUnrequestedProtocolsFail() async throws {
        XCTAssertFalse(RDP.startsTLS(.selected(RDP.protocolHybridEx, flags: 0))); XCTAssertFalse(RDP.startsTLS(.selected(RDP.protocolRDSAAD, flags: 0)))
        XCTAssertEqual(RDP.findings(.selected(RDP.protocolHybridEx, flags: 0)).first?.severity, .fail)
        XCTAssertTrue(RDP.findings(.selected(RDP.protocolHybridEx, flags: 0)).first!.title.contains("not requested"))
        for mode in ["rdp-hybridex", "rdp-aad"] {
            let r = try await rdp(mode)
            XCTAssertNotNil(r.error, mode); XCTAssertTrue(r.chain.isEmpty, mode)
            XCTAssertEqual(r.findings.map(\.id), ["rdp-neg"], mode); XCTAssertTrue(r.findings[0].title.contains("not requested"), mode)
        }
    }
    func testLengthChecks() {
        // X.224 length indicator longer than the bytes received.
        XCTAssertThrowsError(try RDP.parseConfirm([0x0E, 0xD0, 0, 0, 0x12, 0x34, 0, 0x02, 0x00, 0x08]))
        XCTAssertThrowsError(try RDP.parseConfirm([0x20, 0xD0, 0, 0, 0x12, 0x34, 0]))
        // TPKT length outside 11...1024.
        XCTAssertThrowsError(try RDP.tpktLength([3, 0, 0, 10])); XCTAssertNoThrow(try RDP.tpktLength([3, 0, 0, 11]))
        XCTAssertNoThrow(try RDP.tpktLength([3, 0, 0x04, 0x00])); XCTAssertThrowsError(try RDP.tpktLength([3, 0, 0x04, 0x01]))
        XCTAssertThrowsError(try RDP.tpktLength([3, 0, 0]))
    }
    func testSplitReadNegotiation() async throws {
        let r = try await rdp("rdp-split")
        XCTAssertNil(r.error, "\(r.error ?? "")"); XCTAssertEqual(sev(r.findings, "rdp-neg"), .pass); XCTAssertEqual(r.chain.count, 2)
    }
    func testExpiredSelfSignedIsNotDowngraded() async throws {
        let r = try await rdp("rdp-hybrid", chain: "rdp-selfexpired.pem", key: "rdp-selfexpired.key", sni: "host1.example.test")
        XCTAssertEqual(sev(r.findings, "rdp-selfsigned"), .warning)
        XCTAssertEqual(sev(r.findings, "trust"), .fail, "expired self-signed must stay a trust failure")
        XCTAssertNotNil(r.findings.first { $0.id.hasPrefix("exp-") && $0.severity == .fail })
        // A valid self-signed certificate evaluated after its expiry is not downgraded either.
        let valid = try Certificate(der: PEM.blocks(String(decoding: try Data(contentsOf: fx("rdp-selfsigned.pem")), as: UTF8.self))[0].der)
        let t = Target(name: "", host: "host1.example.test", service: .rdp)
        let f = Remote.adjust([Finding("trust", .fail, .trust, "Not trusted")], chain: [valid], target: t, now: valid.notAfter.addingTimeInterval(86_400))
        XCTAssertEqual(sev(f, "trust"), .fail)
        XCTAssertEqual(sev(Remote.adjust([Finding("trust", .fail, .trust, "Not trusted")], chain: [valid], target: t), "trust"), .warning)
        // Not the only certificate: no downgrade.
        let ca = try Certificate(der: PEM.blocks(String(decoding: try Data(contentsOf: fx("int.pem")), as: UTF8.self))[0].der)
        XCTAssertEqual(sev(Remote.adjust([Finding("trust", .fail, .trust, "Not trusted")], chain: [valid, ca], target: t), "trust"), .fail)
    }
    func testWinRMLikelyWithoutSchemeOrHTTPAPI() async throws {
        XCTAssertTrue(WinRMHTTP.findings(WinRMHTTP.Response(status: 401, schemes: [], server: nil), port: 5985).first!.title.hasPrefix("Likely"))
        XCTAssertTrue(WinRMHTTP.findings(WinRMHTTP.Response(status: 404, schemes: [], server: "Microsoft-HTTPAPI/2.0"), port: 5985).first!.title.hasPrefix("Likely"))
        XCTAssertFalse(WinRMHTTP.findings(WinRMHTTP.Response(status: 401, schemes: ["Negotiate"], server: "Microsoft-HTTPAPI/2.0"), port: 5985).first!.title.hasPrefix("Likely"))
        for mode in ["winrm-http-noscheme", "winrm-http-httpapi"] {
            let (p, port) = try server(mode); defer { p.terminate() }
            let r = await WinRMHTTP.check(host: "127.0.0.1", port: port, timeout: 5)
            XCTAssertEqual(r.findings.first?.severity, .warning, mode); XCTAssertTrue(r.findings.first!.title.hasPrefix("Likely"), mode)
        }
    }
    func testRemoteFormState() {
        var f = RemoteForm()
        XCTAssertEqual(f.service, .rdp); XCTAssertEqual(f.port, "3389"); XCTAssertFalse(f.canRun)
        f.select(.winrmHTTPS); XCTAssertEqual(f.port, "5986"); f.checkHTTP = true; XCTAssertTrue(f.runsHTTPCheck)
        f.select(.rdGateway); XCTAssertEqual(f.port, "443"); XCTAssertFalse(f.checkHTTP); XCTAssertFalse(f.runsHTTPCheck)
        f.checkHTTP = true; XCTAssertFalse(f.runsHTTPCheck, "HTTP check never runs for non-WinRM services")
        f.host = "  h.example.test "; f.expected = " n.example.test "; f.port = "x"
        XCTAssertTrue(f.canRun); XCTAssertEqual(f.target.host, "h.example.test"); XCTAssertEqual(f.target.expectedName, "n.example.test")
        XCTAssertEqual(f.target.platform, .windowsRDGateway)
        XCTAssertThrowsError(try f.target.validate(), "bad port must be rejected, so the pane does not switch to Targets")
        f.port = "8443"; XCTAssertNoThrow(try f.target.validate())
        XCTAssertEqual(Advisor.replace(.windowsIIS, host: "h", reason: .expiry, service: .https).title, "Windows IIS / RD Gateway: bind the new certificate")
    }
    func testRefusedKBExtensionsIncludeLauncherTypes() {
        for e in ["fileloc", "webloc", "inetloc", "jar", "dmg", "url", "osax", "plugin", "bundle", "service", "shortcut", "saver", "qlgenerator", "mdimporter"] { XCTAssertTrue(KB.refusedExtensions.contains(e), e) }
    }

    // MARK: Guidance
    func testGuidanceIsCopyOnlyQuotedAndGeneric() {
        let t = Target(name: "", host: "o'brien.example.test", service: .winrmHTTPS)
        let all = [RemoteAdvisor.rdpBinding(), RemoteAdvisor.rdpSecurity, RemoteAdvisor.rdgBinding(), RemoteAdvisor.winrmListener(host: t.host), RemoteAdvisor.winrmHTTP(host: t.host),
                   RemoteAdvisor.firewall(.rdp), RemoteAdvisor.firewall(.rdGateway), RemoteAdvisor.firewall(.winrmHTTPS)]
        let cmds = all.flatMap(\.commands).joined(separator: "\n")
        XCTAssertTrue(cmds.contains("SSLCertificateSHA1Hash = 'THUMBPRINT'")); XCTAssertTrue(cmds.contains("Set-CimInstance")); XCTAssertTrue(cmds.contains("wmic"))
        XCTAssertTrue(cmds.contains("Set-Item -Path RDS:\\GatewayServer\\SSLCertificate\\Thumbprint -Value 'THUMBPRINT'"))
        XCTAssertTrue(cmds.contains("New-Item -Path WSMan:\\localhost\\Listener -Transport HTTPS -Address * -HostName 'o''brien.example.test' -CertificateThumbPrint 'THUMBPRINT'"))
        XCTAssertTrue(cmds.contains("-ConnectionBroker 'broker.example.com'"))
        XCTAssertFalse(cmds.lowercased().contains("password ") && cmds.contains("-Password '"), "no inline passwords")
        XCTAssertEqual(Advisor.guidance(for: .expiry, platform: .generic, target: Target(name: "", host: "h", service: .rdp)).first?.title, "RDP host: bind a CA-issued certificate")
        XCTAssertEqual(Advisor.guidance(for: .hostname, platform: .windowsIIS, target: Target(name: "", host: "h", service: .rdGateway)).first?.title, "RD Gateway: bind the gateway certificate")
        XCTAssertEqual(Advisor.guidance(for: .eku, platform: .generic, target: t).first?.title, "WinRM: HTTPS listener with the right certificate")
        XCTAssertEqual(RemoteAdvisor.guidance(for: Finding("rdp-nla", .warning, .remote, "t", kind: "rdp-nla"), target: nil).first?.title, "RDP host: require TLS and Network Level Authentication")
        XCTAssertTrue(RemoteAdvisor.guidance(for: Finding("winrm-http", .info, .remote, "t", kind: "winrm-http"), target: nil).isEmpty)
        XCTAssertTrue(Probe.opensslCommand(Target(name: "", host: "h", service: .rdp)).hasPrefix("nmap -Pn -p 3389"))
        XCTAssertTrue(Probe.opensslCommand(Target(name: "", host: "h", service: .winrmHTTPS)).contains("-connect h:5986"))
        XCTAssertEqual(Shell.psQuote("a'b"), "'a''b'")
        XCTAssertTrue(KB.allKeys.contains(KB.rdp) && KB.allKeys.contains(KB.rdGateway) && KB.allKeys.contains(KB.winrm))
    }
    func testServiceDefaultsAndTargetsRoundTrip() throws {
        XCTAssertEqual(Service.rdp.defaultPort, 3389); XCTAssertEqual(Service.rdGateway.defaultPort, 443); XCTAssertEqual(Service.winrmHTTPS.defaultPort, 5986)
        XCTAssertTrue(Service.rdp.usesUpgrade); XCTAssertFalse(Service.rdGateway.usesUpgrade); XCTAssertFalse(Service.winrmHTTPS.usesUpgrade)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("tg-\(UUID().uuidString)"); defer { try? FileManager.default.removeItem(at: dir) }
        let s = TargetStore(url: dir.appendingPathComponent("targets.json"))
        let ts = [Target(name: "a", host: "h1", service: .rdp), Target(name: "b", host: "h2", service: .rdGateway), Target(name: "c", host: "h3", service: .winrmHTTPS)]
        try s.save(ts); XCTAssertEqual(try s.load(), ts)
    }
}
