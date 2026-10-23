import XCTest
/// Munki / FileMaker / Retrospect / HP EWS / Barracuda WAF (0.8.0) and review carry-overs. SYNTHETIC-* fixtures; live tests use the loopback fake server only.
final class VendorTests: XCTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }
    func chain(_ n: String) throws -> [Certificate] { try PEM.blocks(String(decoding: try Data(contentsOf: fx(n)), as: UTF8.self)).map { try Certificate(der: $0.der) } }
    let untrusted = [Finding("trust", .fail, .trust, "Not trusted")]
    func t(_ s: Service, port: Int? = nil) -> Target { Target(name: "", host: "dev.example.test", port: port ?? s.defaultPort, service: s) }

    func testServices() {
        XCTAssertEqual(Service.barracudaManagement.defaultPort, 8443); XCTAssertEqual(Service.fileMaker.defaultPort, 443)
        for s in VendorForm.services { XCTAssertTrue(s.isVendor, s.rawValue); XCTAssertNotNil(s.defaultPlatform) }
        XCTAssertFalse(Service.https.isVendor)
    }
    func testDetectors() throws {
        let fms = try chain("SYNTHETIC-fms-default.pem")[0], hp = try chain("SYNTHETIC-hp-default.pem")[0], waf = try chain("SYNTHETIC-barracuda-default.pem")[0]
        let retro = try chain("SYNTHETIC-retrospect-default.pem")[0], gen = try chain("SYNTHETIC-openssl-default.pem")[0], custom = try chain("SYNTHETIC-fms-custom.pem")[0]
        XCTAssertTrue(Vendor.isFileMakerDefault(fms)); XCTAssertFalse(Vendor.isFileMakerDefault(custom)); XCTAssertFalse(Vendor.isFileMakerDefault(hp))
        XCTAssertTrue(Vendor.isHPDefault(hp)); XCTAssertFalse(Vendor.isHPDefault(waf))
        XCTAssertTrue(Vendor.isBarracudaDefault(waf)); XCTAssertFalse(Vendor.isBarracudaDefault(fms))
        XCTAssertTrue(Vendor.isRetrospectDefault(retro)); XCTAssertTrue(Vendor.isGenericDefault(gen)); XCTAssertFalse(Vendor.isGenericDefault(custom))
    }
    func testHPDetectorRequiresOrgOrHPName() throws {
        XCTAssertTrue(Vendor.isHPDefault(try chain("SYNTHETIC-hp-ljname.pem")[0]), "CN 'HP' followed by a space")
        XCTAssertTrue(Vendor.isHPDefault(try chain("SYNTHETIC-hp-hpinc.pem")[0]), "O=HP Inc.")
        let hpc = try chain("SYNTHETIC-hpc-lookalike.pem")
        XCTAssertFalse(Vendor.isHPDefault(hpc[0]), "hpc01 is not an HP printer default")
        for n in ["HP", "HP_1A2B3C", "HP-LJ", "NPI0A1B2C"] { XCTAssertTrue(Vendor.isHPName(n), n) }
        for n in ["hpc01", "HPE-switch", "hpux", "NPIX", "NPIzz1234", ""] { XCTAssertFalse(Vendor.isHPName(n), n) }
        let r = Vendor.adjust(untrusted, chain: hpc, target: t(.hpPrinter), tlsVersion: "TLS 1.2")
        XCTAssertNil(sev(r, "hp-default")); XCTAssertEqual(sev(r, "hp-selfsigned"), .warning); XCTAssertEqual(sev(r, "trust"), .fail, "a look-alike does not downgrade trust")
    }
    func testMunkiLoadRefusesSymlinkAndOversize() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("SYNTHETIC-munki-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: dir) }
        let link = dir.appendingPathComponent("link.plist")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: fx("SYNTHETIC-ManagedInstalls.plist"))
        XCTAssertThrowsError(try Munki.load(link)) { XCTAssertTrue($0.localizedDescription.contains("symbolic"), $0.localizedDescription) }
        let big = dir.appendingPathComponent("big.plist"); try Data(count: FileCheck.maxFileSize + 1).write(to: big)
        XCTAssertThrowsError(try Munki.load(big)) { XCTAssertTrue($0.localizedDescription.contains("2 MB"), $0.localizedDescription) }
        XCTAssertEqual(try Munki.load(fx("SYNTHETIC-ManagedInstalls.plist")).repoURL, "https://munki.example.test/repo")
        XCTAssertEqual(sev(Munki.settingsFindings(MunkiSettings()), "munki-profiles"), .info)
    }
    func testFileMakerAdjust() throws {
        let d = Vendor.adjust(untrusted, chain: try chain("SYNTHETIC-fms-default.pem"), target: t(.fileMaker, port: 5003), tlsVersion: "TLS 1.2")
        XCTAssertEqual(sev(d, "fms-default"), .fail); XCTAssertEqual(sev(d, "fms-5003"), .info); XCTAssertEqual(sev(d, "vendor-fp"), .info); XCTAssertEqual(sev(d, "trust"), .fail)
        let c = Vendor.adjust([], chain: try chain("SYNTHETIC-fms-custom.pem"), target: t(.fileMaker), tlsVersion: nil)
        XCTAssertNil(sev(c, "fms-default")); XCTAssertNil(sev(c, "fms-selfsigned"))
    }
    func testHPAdjust() throws {
        let c = try chain("SYNTHETIC-hp-default.pem")
        let old = Vendor.adjust(untrusted, chain: c, target: t(.hpPrinter), tlsVersion: "TLS 1.0")
        XCTAssertEqual(sev(old, "hp-default"), .warning); XCTAssertEqual(sev(old, "hp-weakkey"), .fail); XCTAssertEqual(sev(old, "hp-protocol"), .fail)
        XCTAssertEqual(sev(old, "trust"), .warning, "factory self-signed in validity: downgraded, fingerprint shown")
        let new = Vendor.adjust([], chain: c, target: t(.hpPrinter), tlsVersion: "TLS 1.3")
        XCTAssertEqual(sev(new, "hp-protocol"), .info); XCTAssertTrue(new.first { $0.id == "hp-protocol" }!.title.contains("not tested"))
    }
    func testBarracudaRetrospectMunkiAdjust() throws {
        let w = try chain("SYNTHETIC-barracuda-default.pem")
        let svc = Vendor.adjust(untrusted, chain: w, target: t(.barracudaService), tlsVersion: nil)
        XCTAssertEqual(sev(svc, "waf-default"), .fail); XCTAssertEqual(sev(svc, "trust"), .fail)
        let mg = Vendor.adjust(untrusted, chain: w, target: t(.barracudaManagement), tlsVersion: nil)
        XCTAssertEqual(sev(mg, "waf-default"), .warning); XCTAssertEqual(sev(mg, "trust"), .warning)
        XCTAssertEqual(sev(Vendor.adjust([], chain: w, target: t(.barracudaService, port: 8443), tlsVersion: nil), "waf-port"), .info)
        let r = Vendor.adjust(untrusted, chain: try chain("SYNTHETIC-retrospect-default.pem"), target: t(.retrospectConsole), tlsVersion: nil)
        XCTAssertEqual(sev(r, "retro-scope"), .info); XCTAssertEqual(sev(r, "retro-default"), .warning)
        XCTAssertEqual(sev(Vendor.adjust([], chain: try chain("SYNTHETIC-openssl-default.pem"), target: t(.munkiRepo), tlsVersion: nil), "munki-default"), .fail)
        XCTAssertEqual(Vendor.adjust(untrusted, chain: w, target: t(.https), tlsVersion: nil), untrusted, "non-vendor services untouched")
    }
    func testHandshakeNotes() {
        XCTAssertEqual(Vendor.handshakeFailureNote(t(.retrospectConsole, port: 22024))?.id, "retro-port")
        XCTAssertEqual(Vendor.handshakeFailureNote(t(.retrospectConsole, port: 497))?.id, "retro-port")
        XCTAssertEqual(Vendor.handshakeFailureNote(t(.fileMaker, port: 5003))?.id, "fms-port")
        XCTAssertNil(Vendor.handshakeFailureNote(t(.fileMaker)))
    }
    func testMunkiParse() throws {
        let m = try Munki.parse(try Data(contentsOf: fx("SYNTHETIC-ManagedInstalls.plist")))
        XCTAssertEqual(m.repoURL, "https://munki.example.test/repo"); XCTAssertEqual(m.repoTarget?.host, "munki.example.test"); XCTAssertEqual(m.repoTarget?.port, 443)
        XCTAssertEqual(m.clientKeyPath, "/Library/Managed Installs/certs/client.key")
        XCTAssertThrowsError(try Munki.parse(Data("not a plist".utf8)))
        var h = MunkiSettings(); h.repoURL = "http://munki.example.test/repo"
        XCTAssertEqual(sev(Munki.settingsFindings(h), "munki-url"), .fail); XCTAssertNil(h.repoTarget)
        XCTAssertEqual(sev(Munki.settingsFindings(MunkiSettings()), "munki-url"), .warning)
        var p = MunkiSettings(); p.repoURL = "https://munki.example.test"; p.clientCertificatePath = "/x"
        XCTAssertEqual(sev(Munki.settingsFindings(p), "munki-clientcert"), .warning)
    }
    func plist(cert: String, key: String) throws -> MunkiSettings {
        let d: [String: Any] = ["SoftwareRepoURL": "https://munki.example.test/repo", "UseClientCertificate": true,
                                "ClientCertificatePath": fx(cert).path, "ClientKeyPath": fx(key).path, "SoftwareRepoCACertificate": fx("SYNTHETIC-vendor-ca.pem").path]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("SYNTHETIC-mi-\(UUID().uuidString).plist")
        try PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0).write(to: url); defer { try? FileManager.default.removeItem(at: url) }
        return try Munki.parse(try Data(contentsOf: url))
    }
    func testMunkiInspect() throws {
        let good = Munki.inspect(try plist(cert: "SYNTHETIC-munki-client.pem", key: "SYNTHETIC-munki-client.key"), cert: nil, key: nil, ca: nil)
        XCTAssertFalse(good.chain.isEmpty); XCTAssertFalse(good.findings.contains { $0.severity == .fail }, "\(good.findings.map { "\($0.id):\($0.severity)" })")
        XCTAssertTrue(good.findings.allSatisfy { $0.topic != .stack })
        let bad = Munki.inspect(try plist(cert: "SYNTHETIC-munki-client.pem", key: "SYNTHETIC-munki-other.key"), cert: nil, key: nil, ca: nil)
        XCTAssertTrue(bad.findings.contains { $0.severity == .fail }, "mismatched key must fail")
        let none = Munki.inspect(MunkiSettings(repoURL: "https://m.example.test", useClientCertificate: true), cert: nil, key: nil, ca: nil)
        XCTAssertEqual(sev(none.findings, "munki-pair"), .info)
    }
    func testGuidanceCopyOnly() {
        let hp = VendorAdvisor.hp(host: "printer.example.test")
        XCTAssertTrue(hp.commands[0].contains("-tls1 ")); XCTAssertTrue(hp.commands[1].contains("-tls1_1"))
        let all = [VendorAdvisor.munki(host: "m.example.test"), VendorAdvisor.fileMaker(host: "f.example.test"), VendorAdvisor.retrospect(host: "r.example.test"), hp,
                   VendorAdvisor.barracuda(host: "w.example.test", management: true), VendorAdvisor.barracuda(host: "w.example.test", management: false)]
        let text = all.flatMap { $0.steps + $0.commands }.joined(separator: "\n")
        XCTAssertTrue(text.contains("fmsadmin")); XCTAssertTrue(text.contains("8443")); XCTAssertFalse(text.contains("BEGIN"))
        XCTAssertEqual(VendorAdvisor.guidance(for: Finding("x", .fail, .vendor, "", "", kind: "waf-cert"), target: t(.barracudaManagement)).first?.title, "Barracuda WAF: management UI certificate")
        XCTAssertTrue(VendorAdvisor.guidance(for: Finding("x", .info, .vendor, "", "", kind: "munki-config"), target: nil).isEmpty)
        for s in VendorForm.services { XCTAssertNotNil(VendorAdvisor.binding(s, host: "h.example.test", why: nil)) }
    }
    func testVendorForm() {
        var f = VendorForm(); XCTAssertFalse(f.canRun); f.host = " fms.example.test "
        XCTAssertEqual(f.target.host, "fms.example.test"); XCTAssertEqual(f.target.platform, .fileMaker); XCTAssertNoThrow(try f.target.validate())
        f.select(.barracudaManagement); XCTAssertEqual(f.target.port, 8443); XCTAssertEqual(f.target.platform, .barracuda)
    }

    // MARK: targets.json safety and back-compat
    func tmpStore() throws -> (TargetStore, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("SYNTHETIC-targets-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (TargetStore(url: dir.appendingPathComponent("targets.json")), dir)
    }
    func testUnreadableTargetsAreBackedUpAndNeverOverwritten() throws {
        let (store, dir) = try tmpStore(); defer { try? FileManager.default.removeItem(at: dir) }
        let bad = Data(#"[{"name":"x","host":"x.example.test","port":443,"service":"Future service"}]"#.utf8)
        try bad.write(to: store.url)
        var lib = TargetLibrary(store: store)
        XCTAssertTrue(lib.savesBlocked); XCTAssertTrue(lib.targets.isEmpty); XCTAssertNotNil(lib.loadError)
        let bak = try XCTUnwrap(lib.backupURL); XCTAssertTrue(bak.lastPathComponent.hasPrefix("targets.json.bak-"))
        XCTAssertEqual(try Data(contentsOf: bak), bad)
        XCTAssertThrowsError(try lib.save([])); XCTAssertThrowsError(try lib.save([Target(name: "a", host: "a.example.test", service: .https)]))
        XCTAssertEqual(try Data(contentsOf: store.url), bad, "the unreadable file is left untouched")
    }
    func testSaveBacksUpBeforeOverwriteAndPrunes() throws {
        let (store, dir) = try tmpStore(); defer { try? FileManager.default.removeItem(at: dir) }
        var lib = TargetLibrary(store: store); XCTAssertFalse(lib.savesBlocked)
        for i in 0..<8 { try lib.save([Target(name: "t\(i)", host: "h\(i).example.test", service: .https)]); Thread.sleep(forTimeInterval: 0.001) }
        let baks = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasPrefix("targets.json.bak-") }
        XCTAssertFalse(baks.isEmpty); XCTAssertLessThanOrEqual(baks.count, 5)
        XCTAssertEqual(try store.load().first?.name, "t7")
    }
    func testTargetDecodeDefaultsForMissingKeys() throws {
        let old = Data(#"[{"host":"old.example.test","service":"FileMaker Server (TLS)"},{"id":"00000000-0000-0000-0000-000000000001","name":"n","host":"h.example.test","port":8443,"service":"HTTPS"}]"#.utf8)
        let t = try JSONDecoder().decode([Target].self, from: old)
        XCTAssertEqual(t[0].port, Service.fileMaker.defaultPort); XCTAssertEqual(t[0].name, "old.example.test")
        XCTAssertEqual(t[0].sni, ""); XCTAssertEqual(t[0].platform, .generic); XCTAssertNil(t[0].fingerprintPin)
        XCTAssertEqual(t[1].port, 8443); XCTAssertEqual(t[1].id.uuidString, "00000000-0000-0000-0000-000000000001")
        let round = try JSONDecoder().decode([Target].self, from: try JSONEncoder().encode(t)); XCTAssertEqual(round, t)
    }
    func testMunkiOverridesByContent() throws {
        let o = try Munki.classifyOverrides([fx("SYNTHETIC-munki-client.key"), fx("SYNTHETIC-munki-client.pem")])
        XCTAssertEqual(o.cert?.lastPathComponent, "SYNTHETIC-munki-client.pem"); XCTAssertEqual(o.key?.lastPathComponent, "SYNTHETIC-munki-client.key")
        XCTAssertThrowsError(try Munki.classifyOverrides([fx("SYNTHETIC-munki-client.key"), fx("SYNTHETIC-munki-other.key")]))
    }

    // MARK: Review carry-overs
    func testSuppliedCASkipsDowngradeWithEKUFailure() throws {
        let c = try chain("SYNTHETIC-logstash-server.pem"), ca = try chain("SYNTHETIC-stack-ca.pem")
        let r = Stack.suppliedCA(untrusted + [Finding("eku", .fail, .eku, "No serverAuth")], chain: c, ca: ca, hostname: "logstash.example.test")
        XCTAssertEqual(sev(r, "trust"), .fail, "an EKU failure blocks the downgrade")
        XCTAssertEqual(sev(Stack.suppliedCA(untrusted, chain: c, ca: ca, hostname: "logstash.example.test"), "trust"), .info)
    }
    func testWildcardAndIPSANDowngrade() throws {
        let ca = try chain("SYNTHETIC-vendor-ca.pem")
        let w = try chain("SYNTHETIC-wild-server.pem")
        XCTAssertEqual(sev(Stack.suppliedCA(untrusted, chain: w, ca: ca, hostname: "a.wild.example.test"), "trust"), .info, "wildcard covers one label")
        XCTAssertEqual(sev(Stack.suppliedCA(untrusted, chain: w, ca: ca, hostname: "a.b.wild.example.test"), "trust"), .fail, "wildcard does not cover two labels")
        let ip = try chain("SYNTHETIC-munki-repo.pem")
        XCTAssertEqual(sev(Stack.suppliedCA(untrusted, chain: ip, ca: ca, hostname: "127.0.0.1"), "trust"), .info, "IP SAN covers the address")
        XCTAssertEqual(sev(Stack.suppliedCA(untrusted, chain: ip, ca: ca, hostname: "127.0.0.2"), "trust"), .fail)
    }
    func testExpiredIntermediateNoDowngrade() throws {
        let r = Stack.suppliedCA(untrusted, chain: try chain("SYNTHETIC-expint-server.pem"), ca: try chain("SYNTHETIC-vendor-ca.pem"), hostname: "expint.example.test")
        XCTAssertEqual(sev(r, "trust"), .fail, "an expired intermediate keeps trust failing")
    }

    // MARK: Loopback fake server
    func server(_ chain: String, _ key: String) throws -> (Process, Int) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = [fx("tls_server.py").path, "tls", fx(chain).path, fx(key).path]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run()
        guard let port = Int(String(decoding: out.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else { p.terminate(); throw XCTSkip("test server did not start") }
        return (p, port)
    }
    func testFileMakerLoopback() async throws {
        let (p, port) = try server("SYNTHETIC-fms-default.pem", "SYNTHETIC-fms-default.key"); defer { p.terminate() }
        let r = await Probe.run(Target(name: "", host: "127.0.0.1", port: port, service: .fileMaker, sni: "fms.example.test"), timeout: 10)
        XCTAssertNil(r.error, r.error ?? ""); XCTAssertEqual(sev(r.findings, "fms-default"), .fail); XCTAssertEqual(sev(r.findings, "vendor-fp"), .info)
    }
    func testBarracudaManagementLoopback() async throws {
        let (p, port) = try server("SYNTHETIC-barracuda-default.pem", "SYNTHETIC-barracuda-default.key"); defer { p.terminate() }
        let r = await Probe.run(Target(name: "", host: "127.0.0.1", port: port, service: .barracudaManagement), timeout: 10)
        XCTAssertNil(r.error, r.error ?? ""); XCTAssertEqual(sev(r.findings, "waf-default"), .warning)
    }
    func testMunkiRepoLoopbackWithCA() async throws {
        let (p, port) = try server("SYNTHETIC-munki-repo.pem", "SYNTHETIC-munki-repo.key"); defer { p.terminate() }
        let t = Target(name: "", host: "127.0.0.1", port: port, service: .munkiRepo, sni: "munki.example.test")
        var r = await Probe.run(t, timeout: 10)
        XCTAssertNil(r.error, r.error ?? ""); XCTAssertEqual(r.chain.count, 2)
        r.findings = Stack.suppliedCA(r.findings, chain: r.chain, ca: try chain("SYNTHETIC-vendor-ca.pem"), hostname: t.verifyName)
        XCTAssertEqual(sev(r.findings, "ca-chain"), .pass); XCTAssertNotEqual(sev(r.findings, "trust"), .fail)
    }
}
