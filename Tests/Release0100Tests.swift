import XCTest
/// 0.10.0: connect-IP override / --resolve, connected-address reporting, split-DNS warning, review backlog.
final class Release0100Tests: PinnedTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    // Must be a real public address: classify() treats the RFC 5737 documentation ranges as .documentation, not .publicAddress.
    static let pub = "93.184.215.14", office = "10.0.0.20"

    func testOverrideKeepsSNIAndExpectedName() throws {
        var t = Target(name: "w", host: "www.example.com", service: .https)
        t.connectIP = "192.0.2.10"
        XCTAssertEqual(t.connectHost, "192.0.2.10"); XCTAssertEqual(t.serverName, "www.example.com"); XCTAssertEqual(t.verifyName, "www.example.com")
        XCTAssertEqual(t.resolverSource, .override)
        t.sni = "sni.example.com"; t.expectedName = "cert.example.com"
        XCTAssertEqual(t.serverName, "sni.example.com"); XCTAssertEqual(t.verifyName, "cert.example.com"); XCTAssertEqual(t.connectHost, "192.0.2.10")
        XCTAssertEqual(Probe.opensslCommand(t), Shell.openssl + " s_client -connect 192.0.2.10:443 -servername sni.example.com -showcerts -verify_hostname cert.example.com </dev/null")
        t.connectIP = "2001:db8::5"; XCTAssertEqual(t.connectEndpoint, "[2001:db8::5]:443")
        XCTAssertNoThrow(try t.validate())
        t.connectIP = "not-an-ip"; XCTAssertThrowsError(try t.validate())
        t.connectIP = "  "; XCTAssertNil(t.connectOverride); XCTAssertEqual(t.resolverSource, .system); XCTAssertNoThrow(try t.validate())
        XCTAssertEqual(Target(name: "", host: "127.0.0.1", service: .https).resolverSource, .literal)
    }

    func testResolveOptionParsing() {
        XCTAssertEqual(Resolution.parseOverride("test.example.test:127.0.0.1")?.ip, "127.0.0.1")
        XCTAssertEqual(Resolution.parseOverride("Test.Example.TEST:127.0.0.1")?.host, "test.example.test")
        XCTAssertEqual(Resolution.parseOverride("h.example.test:2001:db8::1")?.ip, "2001:db8::1")
        XCTAssertEqual(Resolution.parseOverride("h.example.test:[2001:db8::1]")?.ip, "2001:db8::1")
        for bad in ["h.example.test", "h.example.test:", "h.example.test:999.1.1.1", ":127.0.0.1", "127.0.0.1:127.0.0.2", "h example:127.0.0.1"] { XCTAssertNil(Resolution.parseOverride(bad), bad) }
    }

    func testIPClassification() {
        let cases: [(String, IPClass)] = [("10.1.2.3", .rfc1918), ("172.16.0.1", .rfc1918), ("172.31.255.255", .rfc1918), ("172.32.0.1", .publicAddress),
            ("192.168.1.1", .rfc1918), ("100.64.0.1", .cgnat), ("100.127.255.1", .cgnat), ("100.128.0.1", .publicAddress), ("127.0.0.1", .loopback),
            ("169.254.1.1", .linkLocal), ("192.0.2.1", .documentation), ("8.8.8.8", .publicAddress), (Self.pub, .publicAddress), ("0.0.0.0", .unspecified),
            ("224.0.0.1", .multicast), ("::1", .loopback), ("fd00::1", .ula), ("fc12::1", .ula), ("fe80::1", .linkLocal), ("2001:db8::1", .documentation),
            ("2606:4700::1", .publicAddress), ("::ffff:10.0.0.1", .rfc1918), ("::", .unspecified)]
        for (ip, c) in cases { XCTAssertEqual(Resolution.classify(ip), c, ip) }
        XCTAssertNil(Resolution.classify("www.example.com")); XCTAssertNil(Resolution.classify("10.0.0.256"))
        XCTAssertTrue(IPClass.rfc1918.isInternal && IPClass.ula.isInternal && IPClass.cgnat.isInternal)
        XCTAssertFalse(IPClass.publicAddress.isInternal || IPClass.loopback.isInternal || IPClass.linkLocal.isInternal)
    }

    func testSplitDNSWarning() throws {
        let w = try XCTUnwrap(Resolution.splitDNSWarning(host: "sign.example.com", addresses: [Self.pub], source: .system, local: ["fe80::1", Self.office], nameservers: ["10.0.0.2", "1.1.1.1"]))
        XCTAssertEqual(w.severity, .warning); XCTAssertEqual(w.id, "split-dns")
        for s in ["iCloud Private Relay", "Limit IP address tracking", "mask.icloud.com", "hairpin", Self.office, "dig @10.0.0.2 sign.example.com", "--resolve sign.example.com:"] { XCTAssertTrue(w.detail.contains(s), s) }
        XCTAssertFalse(w.detail.contains("1.1.1.1"), "only internal nameservers are listed")
        XCTAssertNotNil(Resolution.splitDNSWarning(host: "a.example.com", addresses: [Self.pub], source: .system, local: ["100.64.0.1"]), "CGNAT counts")
        XCTAssertNotNil(Resolution.splitDNSWarning(host: "a.example.com", addresses: ["2606:4700::1"], source: .system, local: ["fd12::3"]), "ULA counts")
        // Quiet cases.
        XCTAssertNil(Resolution.splitDNSWarning(host: "a.example.com", addresses: ["10.0.0.241"], source: .system, local: [Self.office]), "internal answer")
        XCTAssertNil(Resolution.splitDNSWarning(host: "a.example.com", addresses: [Self.pub], source: .system, local: ["203.0.113.9", "fe80::1"]), "Mac not on a private network")
        XCTAssertNil(Resolution.splitDNSWarning(host: "a.example.com", addresses: [Self.pub], source: .override, local: [Self.office]), "explicit override")
        XCTAssertNil(Resolution.splitDNSWarning(host: Self.pub, addresses: [Self.pub], source: .literal, local: [Self.office]), "IP literal")
        XCTAssertNil(Resolution.splitDNSWarning(host: "a.example.com", addresses: [], source: .system, local: [Self.office]), "no answer")
        XCTAssertNil(Resolution.splitDNSWarning(host: "a.example.com", addresses: [Self.pub, "10.0.0.5"], source: .system, local: [Self.office]), "mixed answer includes an internal address")
        XCTAssertNil(Resolution.splitDNSWarning(host: "a.example.com", addresses: ["127.0.0.1"], source: .system, local: [Self.office]), "loopback")
    }

    func testFirewallHintOnNameMismatch() {
        let t = Target(name: "", host: "sign.example.com", service: .https)
        var r = ProbeResult(target: t); r.connectedIP = Self.pub; r.resolver = .system
        let mismatch = [Finding("host", .fail, .hostname, "Certificate does not cover sign.example.com")]
        let f = Probe.addressFindings(t, r, mismatch, local: [Self.office], nameservers: { [] })
        XCTAssertEqual(Set(f.map(\.id)), ["connected-ip", "split-dns", "firewall-hint"])
        XCTAssertTrue(f.first { $0.id == "firewall-hint" }!.detail.contains("firewall"))
        XCTAssertEqual(Set(Probe.addressFindings(t, r, [Finding("host", .pass, .hostname, "ok")], local: [Self.office], nameservers: { [] }).map(\.id)), ["connected-ip", "split-dns"])
        XCTAssertEqual(Set(Probe.addressFindings(t, r, mismatch, local: ["203.0.113.9"], nameservers: { [] }).map(\.id)), ["connected-ip"], "no hint without the split-DNS condition")
        var o = r; o.resolver = .override
        XCTAssertEqual(Set(Probe.addressFindings(t, o, mismatch, local: [Self.office], nameservers: { [] }).map(\.id)), ["connected-ip"])
    }

    func testConnectedLineFormatting() {
        XCTAssertEqual(Resolution.connectedLine(host: "www.example.com", ip: "192.0.2.7", port: 443, source: .system), "Connected to www.example.com (192.0.2.7):443 (system resolver)")
        XCTAssertEqual(Resolution.connectedLine(host: "test.example.test", ip: "127.0.0.1", port: 8443, source: .override), "Connected to test.example.test (127.0.0.1):8443 (connect-IP override)")
        XCTAssertEqual(Resolution.connectedLine(host: "www.example.com", ip: "2001:db8::7", port: 443, source: .system), "Connected to www.example.com (2001:db8::7):443 (system resolver)")
        XCTAssertEqual(Resolution.connectedLine(host: "127.0.0.1", ip: "127.0.0.1", port: 443, source: .literal), "Connected to 127.0.0.1:443 (IP literal)")
        XCTAssertEqual(Resolution.connectedLine(host: "::1", ip: "::1", port: 443, source: .literal), "Connected to [::1]:443 (IP literal)")
        XCTAssertEqual(Resolution.connectedLine(host: "www.example.com", ip: nil, port: 443, source: .system), "Connected to www.example.com:443 (system resolver)")
    }

    func testLegacyTargetsJSONLoads() throws {
        let legacy = #"[{"id":"8D0C5D34-9D4B-4B57-9C1B-0D3B2E7F2C11","name":"Web","host":"www.example.com","port":443,"service":"HTTPS","sni":"","expectedName":"","platform":"Generic / unknown","notes":""},{"host":"mail.example.com","service":"SMTP STARTTLS"}]"#
        let ts = try JSONDecoder().decode([Target].self, from: Data(legacy.utf8))
        XCTAssertEqual(ts.count, 2); XCTAssertNil(ts[0].connectIP); XCTAssertEqual(ts[1].port, 587); XCTAssertEqual(ts[0].resolverSource, .system)
        var t = ts[0]; t.connectIP = "10.0.0.241"
        let back = try JSONDecoder().decode(Target.self, from: try JSONEncoder().encode(t))
        XCTAssertEqual(back.connectIP, "10.0.0.241"); XCTAssertEqual(back.connectHost, "10.0.0.241")
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(ts[0]), as: UTF8.self).contains("connectIP"), "no key written when unset")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cc-l-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("targets.json"); try Data(legacy.utf8).write(to: url)
        let lib = TargetLibrary(store: TargetStore(url: url))
        XCTAssertNil(lib.loadError); XCTAssertEqual(lib.targets.count, 2)
    }

    func testLocalAddressesExcludeLoopback() {
        XCTAssertFalse(Resolution.localAddresses().contains { Resolution.classify($0) == .loopback || Resolution.classify($0) == .linkLocal })
    }

    /// Integration: local TLS server on 127.0.0.1, probe test.example.test with --resolve test.example.test:127.0.0.1.
    func testResolveOverrideIntegrationSendsHostnameSNI() async throws {
        let py = URL(fileURLWithPath: "/usr/bin/python3")
        guard FileManager.default.isExecutableFile(atPath: py.path) else { throw XCTSkip("python3 not available") }
        let p = Process(); p.executableURL = py
        p.arguments = [fx("tls_server.py").path, "sni", fx("fullchain.pem").path, fx("leaf.key").path]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run(); defer { p.terminate() }
        let first = String(decoding: out.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let port = Int(first) else { throw XCTSkip("test server did not start: \(first)") }
        let o = try XCTUnwrap(Resolution.parseOverride("test.example.test:127.0.0.1"))
        var t = Target(name: "sni", host: o.host, port: port, service: .https); t.connectIP = o.ip
        let r = await Probe.run(t)
        XCTAssertNil(r.error, "\(r.error ?? "") \(r.transcript)")
        XCTAssertEqual(r.connectedIP, "127.0.0.1"); XCTAssertEqual(r.resolver, .override)
        XCTAssertTrue(r.transcript.contains("Connected to test.example.test (127.0.0.1):\(port) (connect-IP override)"), "\(r.transcript)")
        XCTAssertTrue(r.transcript.contains("TLS handshake complete (SNI test.example.test)"))
        let sni = String(decoding: out.fileHandleForReading.availableData, as: UTF8.self)
        XCTAssertTrue(sni.contains("SNI test.example.test"), sni)
        // The expected name stayed the hostname: the fixture certificate does not cover it, so the name check fails.
        XCTAssertEqual(r.findings.first { $0.id == "host" }?.severity, .fail)
        XCTAssertNil(r.findings.first { $0.id == "split-dns" }, "an explicit override never warns")
        XCTAssertEqual(r.findings.first { $0.id == "connected-ip" }?.severity, .info)
    }

    func testLiteralProbeReportsPeerAddress() async throws {
        let py = URL(fileURLWithPath: "/usr/bin/python3")
        guard FileManager.default.isExecutableFile(atPath: py.path) else { throw XCTSkip("python3 not available") }
        let p = Process(); p.executableURL = py
        p.arguments = [fx("tls_server.py").path, "tls", fx("fullchain.pem").path, fx("leaf.key").path]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run(); defer { p.terminate() }
        guard let port = Int(String(decoding: out.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else { throw XCTSkip("no server") }
        let r = await Probe.run(Target(name: "", host: "127.0.0.1", port: port, service: .https, sni: "test.example.internal"))
        XCTAssertEqual(r.connectedIP, "127.0.0.1"); XCTAssertEqual(r.resolver, .literal)
        XCTAssertTrue(r.transcript.contains("Connected to 127.0.0.1:\(port) (IP literal)"), "\(r.transcript)")
    }

    // MARK: backlog
    func testFileCheckPassesItsOwnDateToTrust() throws {
        // expired.pem is valid only during 2020; the pinned clock is in 2026. Trust must be evaluated at the date FileCheck was given.
        let urls = [fx("expired.pem")]
        let pinned = try XCTUnwrap(FileCheck.inspect(urls, hostname: "test.example.internal", purpose: .tlsServer).findings.first { $0.id == "trust" })
        let inWindow = try XCTUnwrap(FileCheck.inspect(urls, hostname: "test.example.internal", purpose: .tlsServer, now: Date(timeIntervalSince1970: 1_593_561_600)).findings.first { $0.id == "trust" })
        XCTAssertTrue(pinned.detail.contains("outside its validity period"), pinned.detail)
        XCTAssertFalse(inWindow.detail.contains("outside its validity period"), "FileCheck passed its own date to Trust.evaluate: \(inWindow.detail)")
        // And the reverse: a currently valid certificate evaluated at a date after its expiry.
        let later = try XCTUnwrap(FileCheck.inspect([fx("fullchain.pem")], hostname: "test.example.internal", purpose: .tlsServer, now: Date(timeIntervalSince1970: 2_200_000_000)).findings.first { $0.id == "trust" })
        XCTAssertTrue(later.detail.contains("outside its validity period"), later.detail)
        XCTAssertFalse(try XCTUnwrap(FileCheck.inspect([fx("fullchain.pem")], hostname: "test.example.internal", purpose: .tlsServer).findings.first { $0.id == "trust" }).detail.contains("outside its validity period"))
    }

    func testDKIMZoneRecordBoundaries() throws {
        let p = Release091Tests.p
        let blank = "a._domainkey.example.test. IN TXT \"v=DKIM1; k=ed25519; p=\(p)\"\n\n\"v=DMARC1; p=none\""
        let r1 = try DKIM.zoneRecords(blank)
        XCTAssertEqual(r1.count, 2, "a blank line ends the record"); XCTAssertNil(r1[1].owner)
        XCTAssertEqual(try DKIM.record(in: blank).keyType, "ed25519")
        let noOwner = "a._domainkey.example.test. IN TXT \"v=DKIM1; k=ed25519; p=\(p)\"\n    IN TXT \"v=spf1 -all\""
        let r2 = try DKIM.zoneRecords(noOwner)
        XCTAssertEqual(r2.count, 2); XCTAssertEqual(r2[0].owner, "a._domainkey.example.test."); XCTAssertNil(r2[1].owner); XCTAssertEqual(r2[1].value, "v=spf1 -all")
        let ttl = "$TTL 3600\n$ORIGIN example.test.\na._domainkey 300 IN TXT ( \"v=DKIM1; k=ed25519;\"\n    p=\(p) )"
        let r3 = try DKIM.zoneRecords(ttl)
        XCTAssertEqual(r3.count, 1); XCTAssertEqual(r3[0].owner, "a._domainkey")
        XCTAssertEqual(try DKIM.record(in: ttl).publicKey?.material.count, 32, "bare continuation inside parentheses is read")
        let ttlBetween = "a IN TXT \"v=DKIM1; k=ed25519; p=\(p)\"\n$TTL 60\n\"v=DMARC1; p=none\""
        XCTAssertEqual(try DKIM.zoneRecords(ttlBetween).count, 2, "$TTL ends the record")
        let multi = "a IN TXT ( \"v=DKIM1; k=ed25519; \"\n  ; a comment line\n  \"p=\(p)\" )"
        XCTAssertEqual(try DKIM.record(in: multi).publicKey?.material.count, 32, "comment lines inside parentheses are skipped")
        XCTAssertThrowsError(try DKIM.parse(noOwner + "\n  IN TXT \"v=DKIM1; p=\(p)\""), "parse() still takes exactly one record")
    }

    func testPkgTempFolderIs0700() throws {
        let d = try CodeSign.privateTempDir(prefix: "cc-pkgtest-"); defer { try? FileManager.default.removeItem(at: d) }
        let perms = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: d.path)[.posixPermissions] as? NSNumber).intValue
        XCTAssertEqual(perms & 0o777, 0o700)
        XCTAssertTrue(d.lastPathComponent.hasPrefix("cc-pkgtest-")); XCTAssertFalse(d.lastPathComponent.hasSuffix("XXXXXXXX"))
        let d2 = try CodeSign.privateTempDir(prefix: "cc-pkgtest-"); defer { try? FileManager.default.removeItem(at: d2) }
        XCTAssertNotEqual(d2.path, d.path)
    }

    func testPkgTempFolderIsPrivateAndRemoved() throws {
        let before = Set((try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)) ?? []).filter { $0.hasPrefix("cc-pkg-") }
        _ = try? CodeSign.pkg(fx("leaf.pem"))
        let after = Set((try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)) ?? []).filter { $0.hasPrefix("cc-pkg-") }
        XCTAssertEqual(before, after, "temporary folder removed")
    }

    // MARK: build 15 review fixes

    func testWinRMHTTPConnectsToOverrideButSendsHostname() throws {
        XCTAssertTrue(WinRMHTTP.request(host: "winrm.example.test", port: 5985).contains("Host: winrm.example.test:5985\r\n"))
        let py = URL(fileURLWithPath: "/usr/bin/python3")
        guard FileManager.default.isExecutableFile(atPath: py.path) else { throw XCTSkip("python3 not available") }
        let p = Process(); p.executableURL = py; p.arguments = [fx("http_capture.py").path]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run(); defer { p.terminate() }
        guard let port = Int(String(decoding: out.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else { throw XCTSkip("no server") }
        let r = WinRMHTTP.checkSync(host: "winrm.example.test", connect: "127.0.0.1", port: port, timeout: 5)
        p.waitUntilExit()
        let seen = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertTrue(seen.contains("HOST winrm.example.test:\(port)"), seen)
        XCTAssertFalse(seen.contains("HOST 127.0.0.1"))
        XCTAssertEqual(r.transcript.first, "Connected to winrm.example.test (127.0.0.1):\(port) (connect-IP override): plaintext HTTP, explicitly requested")
        XCTAssertEqual(r.findings.first?.id, "winrm-http")
        XCTAssertEqual(WinRMHTTP.checkSync(host: "winrm.example.test", connect: "not-an-ip", port: port).findings.first?.severity, .fail)
    }

    func testConflictingResolveEntries() throws {
        XCTAssertEqual(try Resolution.mergeOverrides(["a.example.test:192.0.2.1", "a.example.test:192.0.2.1"]), ["a.example.test": "192.0.2.1"], "same IP repeated is fine")
        XCTAssertEqual(try Resolution.mergeOverrides(["a.example.test:2001:db8::1", "A.example.test.:[2001:DB8:0::1]"]).count, 1, "same address, different spelling")
        XCTAssertThrowsError(try Resolution.mergeOverrides(["a.example.test:192.0.2.1", "a.example.test:192.0.2.2"])) { XCTAssertEqual($0 as? Resolution.OverrideError, .conflict("a.example.test")) }
        XCTAssertThrowsError(try Resolution.mergeOverrides(["a.example.test:192.0.2.1", "a.example.test.:192.0.2.2"]), "trailing dot is the same host")
        XCTAssertThrowsError(try Resolution.mergeOverrides(["a.example.test:bad"])) { XCTAssertEqual($0 as? Resolution.OverrideError, .invalid("a.example.test:bad")) }
        XCTAssertEqual(try Resolution.mergeOverrides(["a.example.test:192.0.2.1", "b.example.test:192.0.2.2"]).count, 2)
    }

    func testTrailingDotMatching() throws {
        let o = try Resolution.mergeOverrides(["host.example.test.:192.0.2.9"])
        XCTAssertEqual(o, ["host.example.test": "192.0.2.9"])
        XCTAssertEqual(Resolution.override(for: "host.example.test", in: o), "192.0.2.9")
        XCTAssertEqual(Resolution.override(for: "HOST.example.test.", in: o), "192.0.2.9")
        XCTAssertNil(Resolution.override(for: "other.example.test", in: o))
        XCTAssertNil(Resolution.override(for: "host.example.test..", in: o), "only one dot is stripped")
        XCTAssertEqual(Resolution.normalizeHost("Www.Example.COM."), "www.example.com")
    }

    func testIPv6ScopeIDsRejected() {
        for s in ["fe80::1%lo0", "fe80::1%en0", "fe80::1%1"] {
            XCTAssertFalse(Resolution.isIP(s), s); XCTAssertNil(Resolution.classify(s), s)
            XCTAssertNil(Resolution.parseOverride("h.example.test:\(s)"), s); XCTAssertNil(Resolution.parseOverride("h.example.test:[\(s)]"), s)
        }
        var t = Target(name: "", host: "h.example.test", service: .https); t.connectIP = "fe80::1%lo0"
        XCTAssertThrowsError(try t.validate())
        XCTAssertTrue(Resolution.isIP("fe80::1"))
    }

    func testUnreadablePeerIsReportedAsRequested() {
        XCTAssertEqual(Resolution.connectedLine(host: "h.example.test", ip: nil, port: 443, source: .override, requested: "192.0.2.4"),
                       "Connected to h.example.test:443 (connect-IP override, requested 192.0.2.4; peer address unavailable)")
        XCTAssertEqual(Resolution.connectedLine(host: "h.example.test", ip: "192.0.2.4", port: 443, source: .override, requested: "192.0.2.4"),
                       "Connected to h.example.test (192.0.2.4):443 (connect-IP override)")
        var t = Target(name: "", host: "h.example.test", service: .https); t.connectIP = "192.0.2.4"
        var r = ProbeResult(target: t); r.resolver = .override; r.connectedIP = nil
        r.transcript = [Resolution.connectedLine(host: t.host, ip: nil, port: 443, source: .override, requested: "192.0.2.4")]
        let f = Probe.addressFindings(t, r, [], local: [Self.office], nameservers: { [] })
        XCTAssertEqual(f.map(\.id), ["connected-ip"]); XCTAssertTrue(f[0].title.hasPrefix("Requested 192.0.2.4"), f[0].title)
        r.transcript = []
        XCTAssertTrue(Probe.addressFindings(t, r, [], local: [Self.office], nameservers: { [] }).isEmpty, "nothing claimed when no connection was made")
    }

    func testSpecialUseRangesAreNotPublic() {
        let cases: [(String, IPClass)] = [("198.18.0.1", .reserved), ("198.19.255.254", .reserved), ("198.17.255.255", .publicAddress), ("198.20.0.1", .publicAddress),
            ("192.0.0.8", .reserved), ("192.0.1.1", .publicAddress), ("240.0.0.1", .reserved), ("250.1.2.3", .reserved), ("255.255.255.255", .reserved),
            ("239.255.255.255", .multicast), ("64:ff9b::c000:201", .nat64), ("64:ff9b::1", .nat64), ("64:ff9b:1::1", .publicAddress),
            ("fec0::1", .reserved), ("feff::1", .reserved), ("febf::1", .linkLocal)]
        for (ip, c) in cases { XCTAssertEqual(Resolution.classify(ip), c, ip) }
        for ip in ["198.18.0.1", "192.0.0.8", "240.0.0.1", "255.255.255.255", "64:ff9b::c000:201", "fec0::1"] {
            XCTAssertNil(Resolution.splitDNSWarning(host: "a.example.com", addresses: [ip], source: .system, local: [Self.office]), ip)
            XCTAssertFalse(Resolution.classify(ip)!.isInternal, ip)
        }
    }

    // MARK: build 16

    func testTrailingDotStrippedFromSNIAndExpectedName() {
        var t = Target(name: "", host: "www.example.com.", service: .https)
        XCTAssertEqual(t.serverName, "www.example.com", "RFC 6066: no trailing dot in server_name"); XCTAssertEqual(t.verifyName, "www.example.com")
        t.sni = "sni.example.com."; t.expectedName = "cert.example.com."
        XCTAssertEqual(t.serverName, "sni.example.com"); XCTAssertEqual(t.verifyName, "cert.example.com")
        XCTAssertTrue(Probe.opensslCommand(t).contains("-servername sni.example.com -"), Probe.opensslCommand(t))
        t.sni = "sni.example.com"; XCTAssertEqual(t.serverName, "sni.example.com")
        XCTAssertEqual(Target(name: "", host: "198.51.100.5", service: .https).serverName, "198.51.100.5")
        t.sni = "sni.example.com.."; XCTAssertEqual(t.serverName, "sni.example.com.", "only one dot is removed")
    }

    // MARK: build 17

    func testBareDotHostIsRejected() {
        for h in [".", "..", "..."] {
            XCTAssertFalse(Target.validHost(h), h)
            XCTAssertThrowsError(try Target(name: "", host: h, service: .https).validate(), h)
            XCTAssertNil(Resolution.parseOverride("\(h):192.0.2.1"), h)
        }
        XCTAssertThrowsError(try Target(name: "", host: "www.example.com", service: .https, sni: ".").validate())
        XCTAssertThrowsError(try Target(name: "", host: "www.example.com", service: .https, expectedName: ".").validate())
        XCTAssertNoThrow(try Target(name: "", host: "www.example.com.", service: .https).validate())
    }
}
