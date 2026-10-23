import XCTest

final class CertificateCheckerTests: PinnedTestCase {
    /// test.sh copies fixtures outside ~/Documents (the test runner has no Files & Folders permission there).
    static let fixtures = URL(fileURLWithPath: ProcessInfo.processInfo.environment["CC_FIXTURES"] ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures").path)
    func fx(_ name: String) -> URL { Self.fixtures.appendingPathComponent(name) }
    func pem(_ name: String) throws -> [PEM.Block] { PEM.blocks(try String(contentsOf: fx(name))) }
    func cert(_ name: String) throws -> Certificate { try Certificate(der: try pem(name)[0].der) }
    func key(_ name: String) throws -> PublicKeyInfo { let b = try pem(name)[0]; return try PrivateKeyFacts.parse(label: b.label, der: b.der).publicKey }
    func ids(_ f: [Finding], _ s: Severity) -> Set<String> { Set(f.filter { $0.severity == s }.map(\.id)) }

    // MARK: DER / PEM
    func testDERLengthAndOID() throws {
        XCTAssertEqual(DER.length(5), [5]); XCTAssertEqual(DER.length(300), [0x82, 0x01, 0x2C])
        let oid = try DER.parse([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
        XCTAssertEqual(oid.oid, "1.2.840.10045.3.1.7")
        XCTAssertThrowsError(try DER.parse([0x30, 0x05, 0x01]))
        XCTAssertThrowsError(try DER.parse([0x30, 0x85, 1, 1, 1, 1, 1]))
    }
    func testTimes() throws {
        let utc = try DER.parse(DER.tlv(0x17, Array("491231235959Z".utf8)))
        let gen = try DER.parse(DER.tlv(0x18, Array("20500101000000Z".utf8)))
        let old = try DER.parse(DER.tlv(0x17, Array("500101000000Z".utf8)))
        var cal = Calendar(identifier: .gregorian); cal.timeZone = TimeZone(identifier: "UTC")!
        XCTAssertEqual(cal.component(.year, from: utc.time!), 2049)
        XCTAssertEqual(cal.component(.year, from: gen.time!), 2050)
        XCTAssertEqual(cal.component(.year, from: old.time!), 1950)
        XCTAssertNil(try DER.parse(DER.tlv(0x17, Array("49123123595Z".utf8))).time)
    }
    func testPEMBlocks() throws {
        let blocks = try pem("fullchain.pem")
        XCTAssertEqual(blocks.count, 2); XCTAssertEqual(blocks.map(\.label), ["CERTIFICATE", "CERTIFICATE"])
        XCTAssertTrue(PEM.blocks("no pem here").isEmpty)
    }

    // MARK: X.509
    func testLeafFields() throws {
        let c = try cert("leaf.pem")
        XCTAssertEqual(c.subject.commonName, "test.example.internal")
        XCTAssertEqual(c.issuer.commonName, "Test Issuing CA")
        XCTAssertEqual(c.version, 3)
        XCTAssertEqual(c.publicKey.algorithm, .rsa(bits: 2048))
        XCTAssertEqual(c.signatureAlgorithm, "sha256WithRSA")
        XCTAssertTrue(c.dnsNames.contains("*.wild.example.internal"))
        XCTAssertTrue(c.ipAddresses.contains("198.51.100.5"))
        XCTAssertEqual(c.extendedKeyUsage, [OID.serverAuth])
        XCTAssertEqual(c.isCA, false)
        XCTAssertNotNil(c.subjectKeyID); XCTAssertNotNil(c.authorityKeyID)
        XCTAssertEqual(c.sha256.count, 95)
        let der = try Certificate(der: [UInt8](Data(contentsOf: fx("leaf.der"))))
        XCTAssertEqual(der.sha256, c.sha256)
        XCTAssertEqual(try cert("int.pem").isCA, true)
    }
    func testHostnameMatching() throws {
        let c = try cert("leaf.pem")
        XCTAssertTrue(c.matches(hostname: "test.example.internal").matched)
        XCTAssertTrue(c.matches(hostname: "TEST.example.internal.").matched)
        XCTAssertTrue(c.matches(hostname: "a.wild.example.internal").matched)
        XCTAssertFalse(c.matches(hostname: "a.b.wild.example.internal").matched)
        XCTAssertFalse(c.matches(hostname: "wild.example.internal").matched)
        XCTAssertTrue(c.matches(hostname: "198.51.100.5").matched)
        XCTAssertFalse(c.matches(hostname: "198.51.100.6").matched)
        XCTAssertFalse(c.matches(hostname: "other.example.internal").matched)
        XCTAssertFalse(Certificate.wildcardMatch(pattern: "*.com", host: "example.com"))
        let nosan = try cert("nosan.pem")
        XCTAssertEqual(nosan.matches(hostname: "test.example.internal").viaCommonNameOnly, true)
    }

    // MARK: Analysis
    func testGoodChainPasses() throws {
        let f = FileCheck.inspect([fx("fullchain.pem"), fx("leaf.key")], hostname: "test.example.internal", purpose: .tlsServer).findings
        XCTAssertTrue(ids(f, .pass).isSuperset(of: ["order", "host", "eku", "keymatch-0", "sig", "key-strength"]), "\(f)")
        XCTAssertFalse(f.contains { $0.severity == .fail && $0.id != "trust" }, "\(f.filter { $0.severity == .fail })")
        // Private fixture CA is not in the trust store.
        XCTAssertEqual(f.first { $0.id == "trust" }?.severity, .fail)
    }
    func testMisorderedChain() throws {
        let r = FileCheck.inspect([fx("misordered.pem")], hostname: nil, purpose: .tlsServer)
        XCTAssertEqual(r.findings.first { $0.id == "order" }?.severity, .warning)
        XCTAssertEqual(r.chain.first?.subject.commonName, "test.example.internal")
    }
    func testIncompleteChainNoted() throws {
        let f = FileCheck.inspect([fx("leaf.pem")], hostname: nil, purpose: .tlsServer).findings
        XCTAssertEqual(f.first { $0.id == "top" }?.topic, .chainIncomplete)
    }
    func testHostnameMismatchFails() throws {
        let f = Analysis.evaluate(certificates: [try cert("leaf.pem")], hostname: "mail.example.internal", purpose: .tlsServer)
        XCTAssertEqual(f.first { $0.id == "host" }?.severity, .fail)
    }
    func testExpiredAndNotYetValid() throws {
        let f = Analysis.evaluate(certificates: [try cert("expired.pem")], hostname: nil, purpose: .tlsServer)
        XCTAssertTrue(ids(f, .fail).contains("exp-0"))
        let leaf = try cert("leaf.pem")
        XCTAssertTrue(ids(Analysis.evaluate(certificates: [leaf], hostname: nil, purpose: .tlsServer, now: leaf.notBefore.addingTimeInterval(-86400)), .fail).contains("nb-0"))
        XCTAssertTrue(ids(Analysis.evaluate(certificates: [leaf], hostname: nil, purpose: .tlsServer, now: leaf.notAfter.addingTimeInterval(-10 * 86400)), .warning).contains("exp-0"))
    }
    func testWeakAlgorithms() throws {
        let f = Analysis.evaluate(certificates: [try cert("weak.pem")], hostname: nil, purpose: .tlsServer)
        XCTAssertTrue(ids(f, .fail).isSuperset(of: ["sig-0", "key-0"]), "\(f)")
    }
    func testEKUAndSAN() throws {
        XCTAssertEqual(Analysis.evaluate(certificates: [try cert("client.pem")], hostname: nil, purpose: .tlsServer).first { $0.id == "eku" }?.severity, .fail)
        XCTAssertEqual(Analysis.evaluate(certificates: [try cert("client.pem")], hostname: nil, purpose: .tlsClient).first { $0.id == "eku" }?.severity, .pass)
        let f = Analysis.evaluate(certificates: [try cert("nosan.pem")], hostname: "test.example.internal", purpose: .tlsServer)
        XCTAssertEqual(f.first { $0.id == "san" }?.severity, .warning)
        XCTAssertEqual(f.first { $0.id == "host" }?.severity, .warning)
    }
    func testCALeafWarning() throws {
        let f = Analysis.evaluate(certificates: [try cert("int.pem")], hostname: nil, purpose: .tlsServer)
        XCTAssertEqual(f.first { $0.id == "ca-leaf" }?.severity, .warning)
    }

    // MARK: Keys
    func testKeyFormatsMatch() throws {
        let leaf = try cert("leaf.pem")
        XCTAssertEqual(try key("leaf.key").material, leaf.publicKey.material)          // PKCS#8 RSA
        XCTAssertEqual(try key("leaf.rsa.key").material, leaf.publicKey.material)      // PKCS#1 RSA
        XCTAssertNotEqual(try key("other.key").material, leaf.publicKey.material)
        let ec = try cert("ec.pem")
        XCTAssertEqual(ec.publicKey.algorithm, .ec(curve: "P-256"))
        XCTAssertEqual(try key("ec.key").material, ec.publicKey.material)              // PKCS#8 EC
        XCTAssertEqual(try key("ec.sec1.key").material, ec.publicKey.material)         // SEC1 EC
        XCTAssertEqual(try key("ed25519.key").algorithm, .ed25519)
        let enc = try pem("encrypted.key")[0]
        XCTAssertThrowsError(try PrivateKeyFacts.parse(label: enc.label, der: enc.der)) { XCTAssertEqual($0 as? KeyError, .encrypted) }
    }
    func testKeyMismatchFails() throws {
        let f = FileCheck.inspect([fx("leaf.pem"), fx("other.key")], hostname: nil, purpose: .tlsServer).findings
        XCTAssertEqual(f.first { $0.id == "keymatch-0" }?.severity, .fail)
    }
    func testFindingsNeverContainKeyMaterial() throws {
        let text = try String(contentsOf: fx("leaf.key"))
        let body = text.split(separator: "\n").dropFirst().first.map(String.init) ?? "x"
        let r = FileCheck.inspect([fx("leaf.pem"), fx("leaf.key")], hostname: nil, purpose: .tlsServer)
        let all = r.findings.map { $0.title + $0.detail }.joined()
        XCTAssertFalse(all.contains(body))
        XCTAssertFalse(all.contains("PRIVATE KEY-----"))
    }

    // MARK: Other formats
    func testCSR() throws {
        let csr = try CertificateRequest(der: try pem("leaf.csr")[0].der)
        XCTAssertEqual(csr.subject.commonName, "test.example.internal")
        XCTAssertEqual(Set(csr.dnsNames), ["test.example.internal", "*.wild.example.internal"])
        let f = FileCheck.inspect([fx("leaf.csr"), fx("leaf.pem"), fx("leaf.key")], hostname: nil, purpose: .tlsServer).findings
        XCTAssertEqual(f.first { $0.id == "csr-cert-0" }?.severity, .pass)
        XCTAssertEqual(f.first { $0.id == "csr-keymatch-0-0" }?.severity, .pass)
    }
    func testPKCS7() throws {
        let certs = try FileCheck.pkcs7Certificates([UInt8](Data(contentsOf: fx("bundle.p7b"))))
        XCTAssertEqual(certs.count, 3)
        XCTAssertEqual(Analysis.orderedChain(certs).map { $0.subject.commonName ?? "" }, ["test.example.internal", "Test Issuing CA", "Test Root CA"])
    }
    func testPFXInMemory() throws {
        guard #available(macOS 15.0, *) else { throw XCTSkip("PFX needs macOS 15 memory-only import") }
        let r = FileCheck.inspect([fx("leaf.p12")], hostname: "test.example.internal", purpose: .tlsServer, password: "fixture-only")
        XCTAssertEqual(r.certificates.count, 2, "\(r.findings)")
        XCTAssertEqual(r.findings.first { $0.id == "keymatch-0" }?.severity, .pass)
        let bad = FileCheck.inspect([fx("leaf.p12")], hostname: nil, purpose: .tlsServer, password: "wrong")
        XCTAssertTrue(bad.certificates.isEmpty)
        XCTAssertTrue(bad.findings.contains { $0.severity == .fail && $0.detail.contains("password") })
    }
    func testGarbageRejected() throws {
        let r = FileCheck.inspect(data: [("junk.bin", Data([1, 2, 3, 4]))], hostname: nil, purpose: .tlsServer)
        XCTAssertTrue(r.findings.contains { $0.id == "parse-junk.bin" })
        XCTAssertTrue(r.findings.contains { $0.id == "none" })
    }

    // MARK: Wire formats
    func testLDAPStartTLSWire() {
        let req = Wire.ldapStartTLSRequest()
        XCTAssertEqual(req.count, 31)
        XCTAssertEqual(Array(req.prefix(7)), [0x30, 0x1D, 0x02, 0x01, 0x01, 0x77, 0x18])
        XCTAssertEqual(Wire.ldapExtendedResultCode([0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]), 0)
        XCTAssertEqual(Wire.ldapExtendedResultCode([0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x02, 0x04, 0x00, 0x04, 0x00]), 2)
        XCTAssertNil(Wire.ldapExtendedResultCode([0x30, 0x03, 0x02, 0x01, 0x01]))
    }
    func testMySQLWire() throws {
        var p: [UInt8] = [10] + Array("8.0.36\u{0}".utf8) + [1, 0, 0, 0] + Array("12345678".utf8) + [0, 0xFF, 0xFF]
        XCTAssertEqual(try Wire.parseMySQLGreeting(p), Wire.MySQLGreeting(version: "8.0.36", supportsTLS: true))
        p[p.count - 2] = 0xFF; p[p.count - 1] = 0xF0
        XCTAssertEqual(try Wire.parseMySQLGreeting(p).supportsTLS, false)
        XCTAssertThrowsError(try Wire.parseMySQLGreeting([0xFF, 0x15, 0x04] + Array("Host blocked".utf8)))
        let req = Wire.mysqlSSLRequest()
        XCTAssertEqual(req.count, 36); XCTAssertEqual(Array(req.prefix(4)), [32, 0, 0, 1])
    }
    func testSMTPReply() {
        XCTAssertNil(Wire.smtpReply(["250-mail"]))
        XCTAssertEqual(Wire.smtpReply(["250-mail", "250 STARTTLS"])?.code, 250)
        XCTAssertEqual(Wire.smtpReply(["220"])?.code, 220)
        XCTAssertEqual(Wire.sanitize("ok\u{1B}[31m\r\n"), "ok[31m")
    }

    // MARK: Targets, guidance, hand-off
    func testTargetValidation() throws {
        for bad in ["", "a b", "host;rm", "-oProxy", "x\ny", "$(id)"] {
            XCTAssertThrowsError(try Target(name: "t", host: bad, service: .https).validate(), bad)
        }
        XCTAssertThrowsError(try Target(name: "t", host: "a.b", port: 0, service: .https).validate())
        XCTAssertNoThrow(try Target(name: "t", host: "fe80::1", service: .https).validate())
        let t = Target(name: "DC", host: "198.51.100.2", service: .ldaps, sni: "dc1.ad.example")
        XCTAssertEqual(t.port, 636); XCTAssertEqual(t.verifyName, "dc1.ad.example")
        XCTAssertEqual(Target(name: "", host: "h", service: .ldapStartTLS).port, 389)
        XCTAssertEqual(Target(name: "", host: "h", service: .smtpStartTLS).port, 587)
        XCTAssertEqual(Target(name: "", host: "h", service: .mysql).port, 3306)
    }
    func testTargetStoreRoundTrip() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).appendingPathComponent("targets.json")
        let store = TargetStore(url: url)
        XCTAssertEqual(try store.load(), [])
        let ts = [Target(name: "Mail", host: "mail.example", service: .smtpStartTLS, platform: .zimbra), Target(name: "DB", host: "db.example", service: .mysql)]
        try store.save(ts)
        XCTAssertEqual(try store.load(), ts)
        let perms = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(perms?.intValue, 0o600)
        try FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }
    func testGuidanceCoverage() {
        let actionable: [Topic] = [.expiry, .hostname, .chainOrder, .chainIncomplete, .trust, .keyMismatch, .weakKey, .weakSignature, .eku, .noSAN, .startTLS, .connection]
        for topic in actionable { for p in Platform.allCases {
            let g = Advisor.guidance(for: topic, platform: p, target: Target(name: "", host: "svc.example", service: .https))
            XCTAssertFalse(g.isEmpty, "\(topic) \(p)")
            XCTAssertTrue(g.allSatisfy { !$0.docs.isEmpty || p == .synology || !$0.steps.isEmpty })
        } }
        XCTAssertTrue(Advisor.guidance(for: .trust, platform: .proxmoxBackup).contains { $0.title.contains("fingerprint") })
    }
    func testConfigDefaultsAreGeneric() throws {
        let d = AppConfig()
        XCTAssertEqual(d.organizationName, ""); XCTAssertTrue(d.kbLinks.isEmpty); XCTAssertEqual(d.defaultDomain, "example.com")
        XCTAssertEqual(d.vpnHostPlaceholder, "vpn.example.com"); XCTAssertEqual(d.signingProcedureDoc, "SIGNING-PROCEDURE.md")
        XCTAssertTrue(KB.available(KB.allKeys, config: d).isEmpty, "KB buttons must be hidden without a config")
        XCTAssertNil(d.connectionWorkbenchApp); XCTAssertNil(d.kbRoot)
    }
    func testConfigDecodingAndKBResolution() throws {
        let json = #"{"organizationName":"Example Org","kbRoot":"/tmp/kb","kbLinks":{"pki":"a/pki.md","radiusGuide":"https://docs.example.com/radius","runbook":"~/r.txt","bad":"ftp://x"},"defaultDomain":"example.test"}"#
        let c = try JSONDecoder().decode(AppConfig.self, from: Data(json.utf8))
        XCTAssertEqual(c.organizationName, "Example Org"); XCTAssertEqual(c.defaultDomain, "example.test")
        XCTAssertEqual(c.vpnHostPlaceholder, "vpn.example.com", "missing keys keep defaults")
        XCTAssertEqual(KB.url(KB.pki, config: c)?.path, "/tmp/kb/a/pki.md")
        XCTAssertEqual(KB.url(KB.radiusGuide, config: c)?.absoluteString, "https://docs.example.com/radius")
        XCTAssertEqual(KB.url(KB.runbook, config: c)?.path, NSHomeDirectory() + "/r.txt")
        XCTAssertEqual(KB.label(KB.radiusGuide, config: c), "docs.example.com")
        XCTAssertNil(KB.url(KB.zimbra, config: c))
        XCTAssertEqual(KB.available([KB.zimbra, KB.pki, KB.radiusGuide], config: c), [KB.pki, KB.radiusGuide])
        var noRoot = c; noRoot.kbRoot = nil
        XCTAssertNil(KB.url(KB.pki, config: noRoot), "relative paths need kbRoot")
    }
    func testKBLinksRefuseExecutablesFoldersAndHTTP() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("kb-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("folder"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("Tool.app"), withIntermediateDirectories: true)
        try "x".write(to: dir.appendingPathComponent("doc.md"), atomically: true, encoding: .utf8)
        try "#!/bin/sh\n".write(to: dir.appendingPathComponent("run.command"), atomically: true, encoding: .utf8)
        try "#!/bin/sh\n".write(to: dir.appendingPathComponent("script.txt"), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.appendingPathComponent("script.txt").path)
        defer { try? FileManager.default.removeItem(at: dir) }
        var c = AppConfig(); c.kbRoot = dir.path
        c.kbLinks = ["pki": "doc.md", "runbook": "folder", "checklist": "Tool.app", "zimbra": "run.command", "proxmox": "script.txt",
                     "synology": "http://docs.example.com/x", "pfSense": "https://docs.example.com/x", "mysqlAdmin": "javascript:alert(1)", "ldapRef": "smb://server/share/doc.md",
                     "wgRunbook": "file://" + dir.appendingPathComponent("Tool.app").path]
        XCTAssertNotNil(KB.url(KB.pki, config: c)); XCTAssertNotNil(KB.url(KB.pfSense, config: c))
        for k in [KB.runbook, KB.checklist, KB.zimbra, KB.proxmox, KB.synology, KB.mysqlAdmin, KB.ldapRef, KB.wgRunbook] {
            XCTAssertNil(KB.url(k, config: c), k); XCTAssertNotNil(KB.resolve(k, config: c).problem, k)
        }
        XCTAssertEqual(KB.available(KB.allKeys, config: c), [KB.pki, KB.pfSense])
        // Symlinks are resolved before the checks: a harmless-looking name pointing at a bundle, script or folder is refused.
        let fm = FileManager.default
        try fm.createSymbolicLink(at: dir.appendingPathComponent("guide.md"), withDestinationURL: dir.appendingPathComponent("Tool.app"))
        try fm.createSymbolicLink(at: dir.appendingPathComponent("notes.txt"), withDestinationURL: dir.appendingPathComponent("script.txt"))
        try fm.createSymbolicLink(at: dir.appendingPathComponent("readme.md"), withDestinationURL: dir.appendingPathComponent("folder"))
        try fm.createSymbolicLink(at: dir.appendingPathComponent("alias.md"), withDestinationURL: dir.appendingPathComponent("doc.md"))
        try "x".write(to: dir.appendingPathComponent("Home.webloc"), atomically: true, encoding: .utf8)
        try fm.createSymbolicLink(at: dir.appendingPathComponent("link.txt"), withDestinationURL: dir.appendingPathComponent("Home.webloc"))
        var s = AppConfig(); s.kbRoot = dir.path
        s.kbLinks = ["pki": "guide.md", "runbook": "notes.txt", "checklist": "readme.md", "zimbra": "alias.md", "proxmox": "link.txt", "synology": "Home.webloc"]
        for k in [KB.pki, KB.runbook, KB.checklist, KB.proxmox, KB.synology] { XCTAssertNil(KB.url(k, config: s), k); XCTAssertNotNil(KB.resolve(k, config: s).problem, k) }
        XCTAssertEqual(KB.url(KB.zimbra, config: s)?.lastPathComponent, "doc.md", "a symlink to a document resolves to the document")
        // Broken symlinks: the link keeps its own name; a refused extension on the link name is still refused.
        let brokenDir = dir.appendingPathComponent("broken"); try fm.createDirectory(at: brokenDir, withIntermediateDirectories: true)
        try fm.createSymbolicLink(at: brokenDir.appendingPathComponent("doc.md"), withDestinationURL: brokenDir.appendingPathComponent("missing-target.txt"))
        try fm.createSymbolicLink(at: brokenDir.appendingPathComponent("x.app"), withDestinationURL: brokenDir.appendingPathComponent("missing-target.md"))
        var b = AppConfig(); b.kbRoot = brokenDir.path; b.kbLinks = ["pki": "doc.md", "runbook": "x.app"]
        XCTAssertEqual(KB.resolve(KB.pki, config: b).url?.lastPathComponent, "doc.md", "a broken doc.md keeps its own name")
        XCTAssertNil(KB.resolve(KB.pki, config: b).problem)
        XCTAssertNil(KB.url(KB.runbook, config: b), "a broken x.app is refused")
        XCTAssertTrue(KB.resolve(KB.runbook, config: b).problem?.contains(".app") == true)
    }
    func testConfigLoadFromFileAndErrors() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cfg-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir); AppConfig.use(path: "none") }
        let good = dir.appendingPathComponent("c.json"); try #"{"organizationName":"Example Org"}"#.write(to: good, atomically: true, encoding: .utf8)
        XCTAssertEqual(AppConfig.load(path: good.path).organizationName, "Example Org"); XCTAssertNil(AppConfig.loadError)
        let bad = dir.appendingPathComponent("b.json"); try "{nope".write(to: bad, atomically: true, encoding: .utf8)
        XCTAssertEqual(AppConfig.load(path: bad.path).organizationName, ""); XCTAssertNotNil(AppConfig.loadError)
        XCTAssertEqual(AppConfig.load(path: "none").defaultDomain, "example.com")
    }
    func testWorkbenchHandoff() {
        XCTAssertEqual(WorkbenchHandoff.url(for: Target(name: "", host: "intranet.example", service: .https)), "https://intranet.example")
        XCTAssertEqual(WorkbenchHandoff.url(for: Target(name: "", host: "::1", port: 8443, service: .https)), "https://[::1]:8443")
        XCTAssertNil(WorkbenchHandoff.url(for: Target(name: "", host: "dc", service: .ldaps)))
        XCTAssertEqual(Probe.opensslCommand(Target(name: "", host: "mail", service: .smtpStartTLS)), Shell.openssl + " s_client -connect mail:587 -servername mail -showcerts -verify_hostname mail -starttls smtp </dev/null")
    }

    // MARK: Live loopback probes (Python test server, TLS upgrade per protocol)
    func runServer(_ mode: String) throws -> (Process, Int) {
        let py = URL(fileURLWithPath: "/usr/bin/python3")
        guard FileManager.default.isExecutableFile(atPath: py.path) else { throw XCTSkip("python3 not available") }
        let p = Process(); p.executableURL = py
        p.arguments = [(ProcessInfo.processInfo.environment["CC_FIXTURES"] != nil ? fx("tls_server.py") : Self.fixtures.deletingLastPathComponent().appendingPathComponent("tls_server.py")).path, mode, fx("fullchain.pem").path, fx("leaf.key").path]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run()
        let line = String(decoding: out.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let port = Int(line) else { p.terminate(); throw XCTSkip("test server did not start: \(line)") }
        return (p, port)
    }
    func probe(_ mode: String, _ service: Service, timeout: TimeInterval = 15) async throws -> ProbeResult {
        let (p, port) = try runServer(mode); defer { p.terminate() }
        return await Probe.run(Target(name: mode, host: "127.0.0.1", port: port, service: service, sni: "test.example.internal"), timeout: timeout)
    }
    func assertTLS(_ r: ProbeResult, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNil(r.error, "\(r.error ?? "") \(r.transcript)", file: file, line: line)
        XCTAssertEqual(r.chain.count, 2, file: file, line: line)
        XCTAssertEqual(r.chain.first?.subject.commonName, "test.example.internal", file: file, line: line)
        XCTAssertEqual(r.findings.first { $0.id == "host" }?.severity, .pass, file: file, line: line)
        XCTAssertEqual(r.findings.first { $0.id == "order" }?.severity, .pass, file: file, line: line)
        XCTAssertNotNil(r.tlsVersion, "TLS version not determined", file: file, line: line)
        XCTAssertFalse(r.findings.contains { $0.title == "TLS version not determined" }, file: file, line: line)
    }
    func testProbeImplicitTLS() async throws { assertTLS(try await probe("tls", .https)) }
    func testProbeSMTPStartTLS() async throws { assertTLS(try await probe("smtp", .smtpStartTLS)) }
    func testProbeIMAPStartTLS() async throws { assertTLS(try await probe("imap", .imapStartTLS)) }
    func testProbePOP3STLS() async throws { assertTLS(try await probe("pop3", .pop3StartTLS)) }
    func testProbeLDAPStartTLS() async throws { assertTLS(try await probe("ldap", .ldapStartTLS)) }
    func testProbeMySQLTLS() async throws { assertTLS(try await probe("mysql", .mysql)) }
    func testProbeSMTPWithoutStartTLS() async throws {
        let r = try await probe("smtp-nostarttls", .smtpStartTLS)
        XCTAssertEqual(r.findings.first?.topic, .startTLS)
        XCTAssertTrue(r.error?.contains("STARTTLS") == true)
    }
    func assertRefused(_ mode: String, _ service: Service, _ text: String, file: StaticString = #filePath, line: UInt = #line) async throws {
        let r = try await probe(mode, service)
        XCTAssertEqual(r.findings.first?.topic, .startTLS, "\(r.findings)", file: file, line: line)
        XCTAssertTrue(r.error?.contains(text) == true, r.error ?? "nil", file: file, line: line)
        XCTAssertTrue(r.chain.isEmpty, file: file, line: line)
    }
    func testProbeSTARTTLSInjectionRejected() async throws { try await assertRefused("smtp-inject", .smtpStartTLS, "possible STARTTLS injection") }
    func testProbeSMTP454Refused() async throws { try await assertRefused("smtp-454", .smtpStartTLS, "STARTTLS returned 454") }
    func testProbeIMAPNORefused() async throws { try await assertRefused("imap-no", .imapStartTLS, "IMAP STARTTLS refused") }
    func testProbeIMAPBYE() async throws { try await assertRefused("imap-bye", .imapStartTLS, "closed the session") }
    func testProbePOP3ERRRefused() async throws { try await assertRefused("pop3-err", .pop3StartTLS, "POP3 STLS refused") }
    func testProbeTimeout() async throws {
        let start = Date()
        let r = try await probe("silent", .smtpStartTLS, timeout: 2)
        XCTAssertTrue(r.error?.contains("Timed out") == true, r.error ?? "nil")
        XCTAssertLessThan(Date().timeIntervalSince(start), 6)
    }
    func testProbeReportsTLSVersion() async throws {
        let r = try await probe("tls", .tls)
        XCTAssertTrue(["TLS 1.2", "TLS 1.3"].contains(r.tlsVersion ?? ""), r.tlsVersion ?? "nil")
    }
    func testProbeTimeoutParameterIsLocal() async throws {
        let before = Probe.timeout
        _ = await Probe.run(Target(name: "", host: "127.0.0.1", port: 1, service: .https), timeout: 1)
        XCTAssertEqual(Probe.timeout, before)
    }
    func testSMTPInconsistentCodes() {
        XCTAssertEqual(Wire.smtpReply(["250-mail", "251 STARTTLS"])?.code, -1)
    }
    func testCommandBuildersQuoteHostileInput() {
        let evil = Target(name: "", host: "a;rm -rf ~", service: .smtpStartTLS, sni: "$(id)")
        let cmd = Probe.opensslCommand(evil)
        XCTAssertTrue(cmd.contains("'a;rm -rf ~:587'"), cmd)
        XCTAssertTrue(cmd.contains("'$(id)'"), cmd)
        XCTAssertTrue(cmd.hasPrefix(Shell.openssl))
        XCTAssertEqual(Shell.quote("it's"), "'it'\\''s'")
        XCTAssertEqual(Shell.quote("dc1.ad.example"), "dc1.ad.example")
        XCTAssertEqual(Shell.quote("[fe80::1]:443"), "'[fe80::1]:443'")
        XCTAssertEqual(Shell.quote("a=b"), "'a=b'"); XCTAssertEqual(Shell.quote("50%"), "'50%'")
        let v6 = Probe.opensslCommand(Target(name: "", host: "fe80::1", service: .https))
        XCTAssertTrue(v6.contains("-connect '[fe80::1]:443'"), v6)
        XCTAssertTrue(Shell.openssl.contains("brew --prefix openssl@3") && !Shell.openssl.contains("/opt/homebrew"))
        let csr = Advisor.guidance(for: .expiry, platform: .nginx, target: Target(name: "", host: "svc.example", service: .https)).flatMap(\.commands).first { $0.contains(" req ") }!
        XCTAssertTrue(csr.contains("umask 077 && openssl req"), csr)
        for topic in Topic.allCases { for p in Platform.allCases {
            for g in Advisor.guidance(for: topic, platform: p, target: evil) { for c in g.commands {
                // Remove every single-quoted segment; hostile text must not survive outside quotes.
                let outside = c.replacingOccurrences(of: Shell.openssl, with: "").replacingOccurrences(of: "'[^']*'", with: "", options: .regularExpression)
                XCTAssertFalse(outside.contains("$(") || outside.contains(";rm"), "unquoted input in \(p) \(topic): \(c)")
            } }
        } }
        XCTAssertFalse(Advisor.guidance(for: .trust, platform: .generic, target: Target(name: "", host: "svc.example", service: .https)).flatMap(\.commands).contains { $0.hasPrefix("openssl ") })
    }
    func testProbeConnectionRefused() async throws {
        let r = await Probe.run(Target(name: "", host: "127.0.0.1", port: 1, service: .https), timeout: 5)
        XCTAssertNotNil(r.error); XCTAssertEqual(r.findings.first?.topic, .connection)
    }
}
