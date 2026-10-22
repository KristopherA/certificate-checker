import XCTest

final class IPsecTests: XCTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func d(_ n: String) throws -> Data { try Data(contentsOf: fx(n)) }
    func run(_ files: [String], id: String? = nil) throws -> IPsecReport {
        IPsecCheck.inspect(data: try files.map { ($0, try d($0)) }, expectedIdentifier: id)
    }
    func sev(_ r: IPsecReport, _ id: String) -> Severity? { r.findings.first { $0.id == id }?.severity }
    func b64(_ n: String) throws -> String { try d(n).base64EncodedString() }
    func config(certs: [(refid: String, descr: String, crt: String, prv: String?)], cas: [(String, String, String)], phase1: String = "", doctype: String = "") -> Data {
        var x = "<?xml version=\"1.0\"?>\(doctype)<pfsense>"
        for c in cas { x += "<ca><refid>\(c.0)</refid><descr>\(c.1)</descr><crt>\(c.2)</crt></ca>" }
        for c in certs { x += "<cert><refid>\(c.refid)</refid><descr>\(c.descr)</descr><crt>\(c.crt)</crt>\(c.prv.map { "<prv>\($0)</prv>" } ?? "")</cert>" }
        return Data((x + "<ipsec>\(phase1)</ipsec></pfsense>").utf8)
    }

    func testGoodServerAndCA() throws {
        let r = try run(["ipsec-server.crt", "ipsec-ca.crt", "ipsec-server.key"], id: "vpn.example.test")
        XCTAssertEqual(r.servers.count, 1); XCTAssertEqual(r.cas.count, 1)
        XCTAssertFalse(r.findings.contains { $0.severity == .fail }, "\(r.findings.filter { $0.severity == .fail }.map(\.title))")
        for id in ["srv0-eku", "srv0-eku-ike", "srv0-ku", "srv0-san", "srv0-id", "srv0-key", "srv0-sig", "srv0-lifetime", "srv0-valid", "srv0-chain", "ca0-bc", "ipsec-key-0"] { XCTAssertEqual(sev(r, id), .pass, id) }
        XCTAssertTrue(r.findings.allSatisfy { $0.topic == .ipsec && !$0.kind.isEmpty })
    }
    func testIPIdentifierAndMismatch() throws {
        XCTAssertEqual(sev(try run(["ipsec-server.crt", "ipsec-ca.crt"], id: "203.0.113.10"), "srv0-id"), .pass)
        XCTAssertEqual(sev(try run(["ipsec-server.crt", "ipsec-ca.crt"], id: "other.example.test"), "srv0-id"), .fail)
        XCTAssertEqual(sev(try run(["ipsec-server.crt", "ipsec-ca.crt"]), "srv0-id"), .info)
    }
    func testECDSAServer() throws {
        let r = try run(["ipsec-ec.crt", "ipsec-ca.crt", "ipsec-ec.key"], id: "vpn.example.test")
        XCTAssertEqual(sev(r, "srv0-key"), .pass); XCTAssertTrue(r.findings.first { $0.id == "srv0-key" }!.title.contains("P-256"))
        XCTAssertEqual(sev(r, "ipsec-key-0"), .pass)
    }
    func testBadServer() throws {
        let r = try run(["ipsec-bad.crt", "ipsec-ca.crt"], id: "vpn.example.test")
        for id in ["srv0-eku", "srv0-ku", "srv0-san", "srv0-id", "srv0-key", "srv0-sig"] { XCTAssertEqual(sev(r, id), .fail, id) }
        XCTAssertEqual(sev(r, "srv0-lifetime"), .warning)
        XCTAssertEqual(sev(r, "srv0-eku-ike"), .info)
    }
    func testWildcardIsInfo() throws {
        let r = try run(["ipsec-wild.crt", "ipsec-ca.crt"], id: "vpn.example.test")
        XCTAssertEqual(sev(r, "srv0-id"), .info); XCTAssertEqual(sev(r, "srv0-lifetime"), .pass)
        XCTAssertEqual(sev(r, "srv0-eku-ike"), .info)
    }
    func testMissingCAAndNonCAIssuer() throws {
        XCTAssertEqual(sev(try run(["ipsec-server.crt"]), "srv0-chain"), .fail)
        let r = try run(["ipsec-orphan.crt", "ipsec-fakeca.crt", "ipsec-ca.crt"])
        let orphan = r.servers.firstIndex { $0.cert.subject.commonName == "orphan.example.test" }!
        XCTAssertTrue(r.findings.contains { $0.id.hasPrefix("srv\(orphan)-chain-notca") && $0.severity == .fail }, "\(r.findings.map(\.id))")
    }
    func testKeyMismatchAndCAKey() throws {
        let r = try run(["ipsec-server.crt", "ipsec-ca.crt", "ipsec-other.key"])
        XCTAssertEqual(sev(r, "ipsec-key-0"), .fail)
        let text = r.findings.map { $0.title + $0.detail }.joined()
        let keyBody = try String(contentsOf: fx("ipsec-other.key")).split(separator: "\n")[1]
        XCTAssertFalse(text.contains(keyBody))
    }
    func testPfSenseConfigWithPhase1() throws {
        let good = (refid: "c1", descr: "IKEv2 Server", crt: try b64("ipsec-server.crt"), prv: Optional(try b64("ipsec-server.key")))
        let unused = (refid: "c2", descr: "Web GUI", crt: try b64("ipsec-wild.crt"), prv: String?.none)
        let wrongKey = (refid: "c3", descr: "Broken", crt: try b64("ipsec-ec.crt"), prv: Optional(try b64("ipsec-other.key")))
        let p1 = "<phase1><descr>Mobile IKEv2</descr><iketype>ikev2</iketype><authentication_method>eap-mschapv2</authentication_method><certref>c1</certref><caref>a1</caref></phase1><phase1><descr>Branch</descr><iketype>ikev2</iketype><certref>c3</certref></phase1>"
        let xml = config(certs: [good, unused, wrongKey], cas: [("a1", "VPN CA", try b64("ipsec-ca.crt"))], phase1: p1)
        let r = IPsecCheck.inspect(data: [("config.xml", xml)], expectedIdentifier: "vpn.example.test")
        XCTAssertEqual(r.servers.map(\.label), ["IKEv2 Server", "Broken"])
        XCTAssertEqual(sev(r, "ipsec-unused"), .info)
        XCTAssertEqual(sev(r, "srv0-prv"), .pass); XCTAssertEqual(sev(r, "srv1-prv"), .fail)
        XCTAssertEqual(sev(r, "srv0-chain"), .pass)
        XCTAssertTrue(r.findings.contains { $0.id == "srv0-p1-0" && $0.title.contains("Mobile IKEv2") })
        let leaked = try String(contentsOf: fx("ipsec-server.key")).split(separator: "\n")[1]
        XCTAssertFalse(r.findings.map { $0.title + $0.detail }.joined().contains(leaked))
    }
    func testPhase1MissingCertAndNoPhase1() throws {
        let xml = config(certs: [], cas: [("a1", "VPN CA", try b64("ipsec-ca.crt"))], phase1: "<phase1><descr>P</descr><certref>zz</certref></phase1>")
        let r = IPsecCheck.inspect(data: [("config.xml", xml)])
        XCTAssertEqual(sev(r, "ipsec-p1-missing-zz"), .fail); XCTAssertEqual(sev(r, "ipsec-noserver"), .info); XCTAssertEqual(sev(r, "ca0-bc"), .pass)
    }
    func testDoctypeEntityRefused() throws {
        for dt in ["<!DOCTYPE p [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>", "<!doctype pfsense>"] {
            let r = IPsecCheck.inspect(data: [("config.xml", config(certs: [], cas: [("a", "CA", try b64("ipsec-ca.crt"))], doctype: dt))])
            XCTAssertTrue(r.findings.contains { $0.id == "parse-config.xml" && $0.detail.contains("DOCTYPE") }, dt)
            XCTAssertTrue(r.cas.isEmpty)
        }
    }
    func testBadBase64AndEmpty() {
        let r = IPsecCheck.inspect(data: [("config.xml", Data("<pfsense><cert><descr>X</descr><crt>!!!</crt></cert></pfsense>".utf8))])
        XCTAssertTrue(r.findings.contains { $0.id.hasPrefix("ipsec-bad-") && $0.severity == .fail })
        XCTAssertTrue(IPsecCheck.inspect(data: [("x.xml", Data("<pfsense/>".utf8))]).findings.contains { $0.id == "parse-x.xml" })
    }
    func testGuidanceIsCopyOnlyAndSafe() {
        for kind in ["reissue", "san", "chain", "keymatch"] {
            let g = IPsecAdvisor.guidance(for: Finding("x", .fail, .ipsec, "t", kind: kind), platform: .pfSense, identifier: "vpn.example.test")
            XCTAssertEqual(g.map(\.title).first, "pfSense Cert. Manager")
            XCTAssertTrue(g[0].steps.joined().contains("Diagnostics › Command Prompt"))
            XCTAssertTrue(g.flatMap(\.commands).contains { $0.contains("-ServerAddress 'vpn.example.test'") })
        }
        let evil = IPsecAdvisor.guidance(for: Finding("x", .fail, .ipsec, "t", kind: "san"), platform: .macOS, identifier: "a'; rm -rf /")
        XCTAssertEqual(evil.first?.title, "macOS / iOS configuration profile")
        XCTAssertFalse(evil.flatMap(\.commands).joined().contains("rm -rf"))
        XCTAssertTrue(IPsecAdvisor.docs.allSatisfy { !$0.hasSuffix(".mobileconfig") })
    }

    // MARK: 0.3.0 review
    func entry(_ refid: String, _ descr: String, _ file: String) throws -> (refid: String, descr: String, crt: String, prv: String?) { (refid, descr, try b64(file), nil) }
    func testDisabledPhase1IsSkipped() throws {
        let p1 = "<phase1><descr>Old mobile</descr><disabled/><mobile/><certref>c1</certref></phase1>"
        let r = IPsecCheck.inspect(data: [("config.xml", config(certs: [try entry("c1", "Server", "ipsec-server.crt"), try entry("c2", "Client", "ipsec-bad.crt")], cas: [("a1", "CA", try b64("ipsec-ca.crt"))], phase1: p1))])
        XCTAssertEqual(sev(r, "ipsec-p1-disabled-0"), .info)
        XCTAssertFalse(r.findings.contains { $0.id.hasPrefix("srv0-p1-") })
        XCTAssertEqual(sev(r, "ipsec-nop1"), .info)   // no enabled certificate Phase 1 left
        XCTAssertEqual(r.servers.map(\.label), ["Server"]); XCTAssertEqual(sev(r, "ipsec-notserver"), .info)
    }
    func testMobileVersusSiteToSiteAndMultiplePhase1() throws {
        let p1 = "<phase1><descr>Mobile</descr><mobile>true</mobile><certref>c1</certref><caref>a2</caref></phase1>"
               + "<phase1><descr>PSK branch</descr><authentication_method>pre_shared_key</authentication_method></phase1>"
               + "<phase1><descr>Branch</descr><certref>c1</certref><caref>a2</caref></phase1>"
        let r = IPsecCheck.inspect(data: [("config.xml", config(certs: [try entry("c1", "Server", "ipsec-server.crt")], cas: [("a1", "CA", try b64("ipsec-ca.crt")), ("a2", "Other CA", try b64("ipsec-pl0-root.crt"))], phase1: p1))])
        let mob = r.findings.first { $0.id == "srv0-p1-0" }, s2s = r.findings.first { $0.id == "srv0-p1-2" }
        XCTAssertTrue(mob?.title.contains("mobile clients") == true); XCTAssertTrue(s2s?.title.contains("site-to-site") == true)
        XCTAssertNil(r.findings.first { $0.id == "srv0-p1-1" })
        XCTAssertEqual(sev(r, "srv0-p1ca-0"), .info); XCTAssertEqual(sev(r, "srv0-p1ca-2"), .info)
        XCTAssertTrue(r.findings.first { $0.id == "srv0-p1ca-0" }!.detail.contains("Mobile"))
        XCTAssertFalse(r.findings.first { $0.id == "srv0-p1ca-2" }!.detail.contains("Mobile"))
    }
    func testPre2019CertificateSkipsAppleLimit() throws {
        let r = try run(["ipsec-old.crt", "ipsec-ca.crt"])
        XCTAssertEqual(sev(r, "srv0-lifetime"), .info); XCTAssertEqual(sev(r, "srv0-valid"), .fail)
    }
    func testExpiredIntermediate() throws {
        let r = try run(["ipsec-underexp.crt", "ipsec-intexp.crt", "ipsec-ca.crt"])
        XCTAssertEqual(sev(r, "srv0-chain"), .fail)
        let ci = r.cas.firstIndex { $0.cert.subject.commonName == "intexp.example.test" }!
        XCTAssertEqual(sev(r, "ca\(ci)-valid"), .fail)
        XCTAssertEqual(sev(r, "srv0-ca-before"), .warning)
    }
    func testPathLenViolation() throws {
        let r = try run(["ipsec-plleaf.crt", "ipsec-plint.crt", "ipsec-pl0-root.crt"])
        XCTAssertEqual(sev(r, "srv0-chain-pathlen-2"), .fail, "\(r.findings.map(\.id))")
        XCTAssertEqual(try Certificate(der: PEM.blocks(String(contentsOf: fx("ipsec-pl0-root.crt"))).first!.der).pathLen, 0)
    }
    func testRevocationNoteAndSizeCap() throws {
        XCTAssertEqual(sev(try run(["ipsec-server.crt", "ipsec-ca.crt"]), "ipsec-revocation"), .info)
        XCTAssertEqual(IPsecCheck.maxFileSize, 20 * 1024 * 1024)
    }
    func testKeyParseErrorsNeverContainKeyBytes() throws {
        let body = Data((0..<96).map { UInt8(($0 * 37 + 11) % 256) }).base64EncodedString()
        for label in ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"] {
            let pem = "-----BEGIN \(label)-----\n\(body)\n-----END \(label)-----\n"
            let viaFile = IPsecCheck.inspect(data: [("ipsec-server.crt", try d("ipsec-server.crt")), ("broken.key", Data(pem.utf8))])
            let viaXML = IPsecCheck.inspect(data: [("config.xml", config(certs: [(refid: "c1", descr: "S", crt: try b64("ipsec-server.crt"), prv: Data(pem.utf8).base64EncodedString())], cas: []))])
            for r in [viaFile, viaXML] {
                let text = r.findings.map { $0.title + " " + $0.detail }.joined(separator: "\n")
                XCTAssertFalse(text.contains(String(body.prefix(16))), label)
                XCTAssertFalse(text.contains(Data(body.utf8).base64EncodedString().prefix(16)), label)
            }
            XCTAssertTrue(viaFile.findings.contains { $0.id == "parse-broken.key" && $0.severity == .fail }, label)
            XCTAssertTrue(viaXML.findings.contains { $0.id.hasPrefix("ipsec-prv-") }, label)
            do { _ = try PrivateKeyFacts.parse(label: label, der: [UInt8](Data(base64Encoded: body)!)); XCTFail("parsed garbage") }
            catch { XCTAssertFalse(error.localizedDescription.contains(String(body.prefix(16)))); XCTAssertLessThan(error.localizedDescription.count, 200) }
        }
    }
    func testInvalidIdentifierFallsBackInGuidance() {
        for bad in ["", "a'; Remove-Item C:\\ -Recurse", "vpn example", "-ServerAddress x"] {
            let g = IPsecAdvisor.guidance(for: Finding("x", .fail, .ipsec, "t", kind: "san"), platform: .windowsIIS, identifier: bad)
            XCTAssertEqual(g[0].title, "Windows IKEv2 client (PowerShell as administrator)")
            XCTAssertTrue(g[0].commands.contains { $0.contains("-ServerAddress 'vpn.example.com'") }, bad)
            XCTAssertTrue(g[0].steps.contains { $0.contains("placeholder vpn.example.com") })
            XCTAssertFalse(g.flatMap(\.commands).joined().contains("Remove-Item"))
        }
        let g = IPsecAdvisor.guidance(for: Finding("x", .fail, .ipsec, "t", kind: "san"), platform: .windowsIIS, identifier: "203.0.113.10")
        XCTAssertTrue(g[0].commands.contains { $0.contains("-ServerAddress '203.0.113.10'") })
        XCTAssertTrue(g[0].commands.contains { $0.hasPrefix("Set-VpnConnectionIPsecConfiguration -ConnectionName 'IKEv2 VPN'") })
        XCTAssertTrue(g[0].steps.contains { $0.hasPrefix("Optional: Set-VpnConnectionIPsecConfiguration") })
    }

    // MARK: 0.3.0 approval follow-ups
    func testNegativePathLenIsMalformed() throws {
        var ca = try Certificate(der: PEM.blocks(String(contentsOf: fx("ipsec-ca.crt"))).first!.der)
        try ca.apply(extension: DER.parse([0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0xFF]))
        XCTAssertTrue(ca.basicConstraintsMalformed); XCTAssertNil(ca.pathLen); XCTAssertEqual(ca.isCA, true)
        let f = IPsecCheck.evaluate(ca: IPsecEntry(label: "CA", cert: ca, refid: nil, ownKey: nil), index: 0, now: Date())
        XCTAssertEqual(f.first { $0.id == "ca0-bc-bad" }?.severity, .fail)
    }
    func testSelfIssuedIntermediateNotCountedForPathLen() throws {
        let r = try run(["ipsec-rollleaf.crt", "ipsec-roll.crt", "ipsec-rollroot.crt"])
        XCTAssertFalse(r.findings.contains { $0.id.hasPrefix("srv0-chain-pathlen") }, "\(r.findings.map(\.id))")
        XCTAssertEqual(sev(r, "srv0-chain"), .pass, "\(r.findings.filter { $0.id == "srv0-chain" }.map(\.detail))")
    }
    func testAKIWithoutSKIRootNextToRollover() throws {
        func cert(_ n: String) throws -> Certificate { try Certificate(der: PEM.blocks(String(decoding: try d(n), as: UTF8.self))[0].der) }
        let root = try cert("ipsec-akiroot.crt"), roll = try cert("ipsec-akiroll.crt"), leaf = try cert("ipsec-akileaf.crt")
        XCTAssertNotNil(root.authorityKeyID); XCTAssertNil(root.subjectKeyID)
        XCTAssertTrue(ChainCheck.isSelfSigned(root), "AKI without SKI: treated as self-signed")
        XCTAssertFalse(ChainCheck.isSelfSigned(roll), "rollover: self-issued, AKI ≠ SKI")
        let ch = ChainCheck.chain(for: leaf, pool: [root, roll])
        XCTAssertEqual(ch.map(\.sha256), [leaf, roll, root].map(\.sha256))
        XCTAssertTrue(ChainCheck.verify(ch, now: Date()).ok, ChainCheck.verify(ch, now: Date()).message)
        let r = try run(["ipsec-akileaf.crt", "ipsec-akiroll.crt", "ipsec-akiroot.crt"])
        XCTAssertEqual(sev(r, "srv0-chain"), .pass, "\(r.findings.filter { $0.id.hasPrefix("srv0-chain") }.map(\.detail))")
    }
    // MARK: SYNTHETIC pfSense 2.7 config.xml (generated keys, example.test names; not a real export)
    func testSyntheticPfSenseConfig() throws {
        let r = IPsecCheck.inspect([fx("SYNTHETIC-pfsense-2.7-config.xml")], expectedIdentifier: "vpn.example.test")
        XCTAssertEqual(Set(r.cas.map(\.label)), ["SYNTHETIC Root CA", "SYNTHETIC VPN Intermediate CA"])
        XCTAssertEqual(r.servers.map(\.label), ["SYNTHETIC IKEv2 server", "SYNTHETIC site-to-site"])
        let unused = r.findings.first { $0.id == "ipsec-unused" }
        XCTAssertTrue(unused?.detail.contains("SYNTHETIC OpenVPN server") == true && unused?.detail.contains("webConfigurator") == true)
        XCTAssertEqual(sev(r, "ipsec-p1-disabled-2"), .info)
        XCTAssertTrue(r.findings.first { $0.id == "srv0-p1-0" }?.title.contains("mobile clients") == true)
        XCTAssertTrue(r.findings.first { $0.id == "srv1-p1-1" }?.title.contains("site-to-site") == true)
        // Both Peer CAs (intermediate for mobile, root for site-to-site) are in each server's chain: no p1ca note.
        XCTAssertNil(r.findings.first { $0.id.hasPrefix("srv0-p1ca") || $0.id.hasPrefix("srv1-p1ca") })
        XCTAssertEqual(sev(r, "srv1-id"), .fail)   // the site-to-site cert is fw1.example.test, not the mobile identifier
        for s in ["srv0", "srv1"] { XCTAssertEqual(sev(r, "\(s)-chain"), .pass, s); XCTAssertEqual(sev(r, "\(s)-prv"), .pass, s) }
        XCTAssertTrue(r.findings.first { $0.id == "srv0-chain" }!.detail.contains("SYNTHETIC VPN Intermediate CA → SYNTHETIC Root CA"))
        XCTAssertEqual(sev(r, "srv0-id"), .pass)
        XCTAssertEqual(r.findings.filter { $0.severity == .fail }.map(\.id), ["srv1-id"])
        let xml = try String(contentsOf: fx("SYNTHETIC-pfsense-2.7-config.xml"))
        XCTAssertTrue(xml.contains("SYNTHETIC test fixture"))
        let line = xml.components(separatedBy: "<prv>")[1].split(separator: "\n")[1]
        XCTAssertFalse(r.findings.map { $0.title + $0.detail }.joined().contains(line))
    }
}
