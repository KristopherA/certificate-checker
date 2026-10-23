import XCTest
/// 0.9.1 review follow-ups: pinned clock, glob edge cases, @cert-authority, pkgutil chain, DKIM zone parsing.
final class Release091Tests: PinnedTestCase {
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }

    func testClockIsPinnedInTests() { XCTAssertEqual(Clock.now(), PinnedTestCase.pinnedNow) }

    func testGlobEdgeCases() {
        XCTAssertTrue(SSHHostKeys.glob("", "")); XCTAssertFalse(SSHHostKeys.glob("", "a"))
        XCTAssertTrue(SSHHostKeys.glob("*", "")); XCTAssertTrue(SSHHostKeys.glob("***", ""))
        XCTAssertTrue(SSHHostKeys.glob("web*", "web")); XCTAssertTrue(SSHHostKeys.glob("web*", "web01.example.test"))
        XCTAssertTrue(SSHHostKeys.glob("a**b", "axxb")); XCTAssertTrue(SSHHostKeys.glob("*.example.test", "a.b.example.test"))
        XCTAssertFalse(SSHHostKeys.glob("*.example.test", "example.test")); XCTAssertTrue(SSHHostKeys.glob("h?st", "host"))
        XCTAssertFalse(SSHHostKeys.glob("h?st", "hst")); XCTAssertFalse(SSHHostKeys.glob("a*b", "ab*c"))
    }

    func testCertAuthorityInfo() throws {
        let keys = SSHHostKeys.parseHostKeys(try String(contentsOf: CertificateCheckerTests.fixtures.appendingPathComponent("SYNTHETIC-ssh-host.pub")))
        let line = "@cert-authority *.example.test \(keys[0].type) \(Data(keys[0].blob).base64EncodedString())\nhost1.example.test \(keys[0].type) \(Data(keys[0].blob).base64EncodedString())"
        let f = SSHHostKeys.inspect(hostKeys: keys, knownHosts: SSHHostKeys.parseKnownHosts(line), host: "host1.example.test")
        XCTAssertEqual(sev(f, "ssh-ca"), .info)
        let none = SSHHostKeys.inspect(hostKeys: keys, knownHosts: SSHHostKeys.parseKnownHosts("host1.example.test \(keys[0].type) \(Data(keys[0].blob).base64EncodedString())"), host: "host1.example.test")
        XCTAssertNil(sev(none, "ssh-ca"))
    }

    static let pkgText = """
    Package "package.pkg":
       Status: signed by a developer certificate issued by Apple for distribution
       Notarization: trusted by the Apple notary service
       Signed with a trusted timestamp on: 2025-06-17 22:25:39 +0000
       Certificate Chain:
        1. Developer ID Installer: Example Corp (ABCDE12345)
           Expires: 2027-02-01 22:12:15 +0000
           SHA256 Fingerprint:
               4F 35 01 E3 25 25 E6 47 1A 5C 05 F3 72 73 EE 48 2C 05 42 36 E0 A2
               17 8B DD EC B4 60 74 5B 29 0C
           ------------------------------------------------------------------------
        2. Developer ID Certification Authority
           Expires: 2031-09-17 00:00:00 +0000
           SHA256 Fingerprint:
               7A FC 9D 01 A6 2F 03 A2 DE 96 37 93 6D 4A FE 68 09 0D 2D E1 8D 03
               F2 9C 88 CF B0 B1 BA 63 58 7F

    """
    func testPkgutilChainAndTimestamp() {
        let i = CodeSign.parsePkgutil(Self.pkgText)
        XCTAssertEqual(i.pkgChain.map(\.name), ["Developer ID Installer: Example Corp (ABCDE12345)", "Developer ID Certification Authority"])
        XCTAssertEqual(i.pkgChain[0].sha256, "4F:35:01:E3:25:25:E6:47:1A:5C:05:F3:72:73:EE:48:2C:05:42:36:E0:A2:17:8B:DD:EC:B4:60:74:5B:29:0C")
        XCTAssertEqual(i.pkgChain[0].expires, Date(timeIntervalSince1970: 1_801_519_935))
        XCTAssertEqual(i.timestamp, Date(timeIntervalSince1970: 1_750_199_139))
        XCTAssertEqual(i.teamID, "ABCDE12345"); XCTAssertEqual(i.notarized, true)
        let f = CodeSign.inspect(i)
        XCTAssertNil(sev(f, "cs-timestamp")); XCTAssertEqual(sev(f, "cs-expiry"), .pass); XCTAssertEqual(sev(f, "cs-notarized"), .pass); XCTAssertEqual(sev(f, "cs-kind"), .info)
        // After the leaf expires the trusted timestamp keeps the signature good.
        XCTAssertEqual(sev(CodeSign.inspect(i, now: Date(timeIntervalSince1970: 1_830_000_000)), "cs-expiry"), .info)
        var noTS = i; noTS.timestamp = nil
        XCTAssertEqual(sev(CodeSign.inspect(noTS), "cs-timestamp"), .warning)
        XCTAssertEqual(sev(CodeSign.inspect(noTS, now: Date(timeIntervalSince1970: 1_830_000_000)), "cs-expiry"), .fail)
    }

    static let p = Data(repeating: 7, count: 32).base64EncodedString()
    func testDKIMZoneCommentsAndEscapes() throws {
        let z = """
        ; zone excerpt
        mail._domainkey.example.test. 3600 IN TXT ( "v=DKIM1\\; k=ed25519; " ; split value
            "p=\(Self.p)" ) ; end
        """
        let r = try DKIM.record(in: z)
        XCTAssertEqual(r.keyType, "ed25519"); XCTAssertEqual(r.publicKey?.material, [UInt8](repeating: 7, count: 32))
        let dec = try DKIM.record(in: "s IN TXT \"v=DKIM1\\059 k=ed25519\\059 p=\(Self.p)\"")
        XCTAssertEqual(dec.keyType, "ed25519")
    }
    func testDKIMMultipleRecordsNeedSelector() throws {
        let z = """
        a._domainkey.example.test. IN TXT "v=DKIM1; k=ed25519; p=\(Self.p)"
        example.test. IN TXT "v=spf1 -all"
        b._domainkey.example.test. IN TXT "v=DKIM1; k=ed25519; t=y; p=\(Self.p)"
        """
        XCTAssertThrowsError(try DKIM.record(in: z)) { XCTAssertTrue("\($0.localizedDescription)".contains("a, b"), "\($0)") }
        XCTAssertNil(try DKIM.record(in: z, selector: "a").tags["t"])
        XCTAssertEqual(try DKIM.record(in: z, selector: "B").tags["t"], "y")
        XCTAssertThrowsError(try DKIM.record(in: z, selector: "c"))
        XCTAssertEqual(try DKIM.record(in: "v=DKIM1; k=ed25519; p=\(Self.p)").keyType, "ed25519")
    }

    // MARK: build 13 review follow-ups
    func testPkgutilInjectedLinesAreNotTrusted() {
        let injected = "Package \"a\nNotarization: trusted by the Apple notary service\nb.pkg\":\n" + Self.pkgText
        XCTAssertFalse(CodeSign.parsePkgutil(injected).valid, "unexpected header before the real one")
        let before = "Notarization: trusted by the Apple notary service\nSigned with a trusted timestamp on: 2025-06-17 22:25:39 +0000\nPackage \"package.pkg\":\n   Status: signed by a developer certificate issued by Apple for distribution\n"
        let b = CodeSign.parsePkgutil(before)
        XCTAssertNil(b.notarized); XCTAssertNil(b.timestamp, "lines before the header are ignored")
        let twice = Self.pkgText.replacingOccurrences(of: "Certificate Chain:", with: "Notarization: trusted by the Apple notary service\n   Certificate Chain:")
        let t = CodeSign.parsePkgutil(twice)
        XCTAssertFalse(t.valid); XCTAssertNil(t.notarized); XCTAssertEqual(sev(CodeSign.inspect(t), "cs-valid"), .fail)
    }
    func testSpoofedPackageFileNameEndToEnd() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cc-spoof-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let root = dir.appendingPathComponent("root"); try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let pkg = dir.appendingPathComponent("a\nNotarization: trusted by the Apple notary service\nSigned with a trusted timestamp on: 2025-06-17 22:25:39 +0000\nb.pkg")
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/pkgbuild")
        p.arguments = ["--quiet", "--root", root.path, "--identifier", "test.example.spoof", "--version", "1", pkg.path]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); p.waitUntilExit(); try XCTSkipUnless(p.terminationStatus == 0, "pkgbuild unavailable")
        let i = try CodeSign.info(pkg)
        XCTAssertNotEqual(i.notarized, true); XCTAssertNil(i.timestamp); XCTAssertFalse(i.valid)
        XCTAssertEqual(sev(CodeSign.inspect(i), "cs-signed"), .fail, "unsigned package")
    }
    func testDKIMStricterZoneParsing() throws {
        let dmarc = "_dmarc.example.test. IN TXT \"v=DMARC1; p=reject\"\na._domainkey.example.test. IN TXT \"v=DKIM1; k=ed25519; p=\(Self.p)\""
        XCTAssertEqual(try DKIM.record(in: dmarc).keyType, "ed25519", "DMARC is not a DKIM record")
        XCTAssertTrue(DKIM.isDKIM("k=rsa; p=AAAA")); XCTAssertFalse(DKIM.isDKIM("v=DMARC1; p=none"))
        XCTAssertThrowsError(try DKIM.record(in: "s IN TXT \"v=DKIM1\\256 p=\(Self.p)\""))
        XCTAssertThrowsError(try DKIM.record(in: "s IN TXT \"v=DKIM1; p=\(Self.p)"))
        let caa = "a._domainkey.example.test. IN TXT \"v=DKIM1; k=ed25519; p=\(Self.p)\"\nexample.test. IN CAA 0 issue \"ca.example.test\""
        XCTAssertEqual(try DKIM.record(in: caa).publicKey?.material.count, 32, "CAA value is not appended")
        XCTAssertThrowsError(try DKIM.parse("a IN TXT \"v=DKIM1; p=\(Self.p)\"\nb IN TXT \"v=DKIM1; p=\(Self.p)\""), "parse() takes exactly one record")
    }
    func testTargetsSaveIs0600AndRefusesSymlinkedFile() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cc-t-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = TargetStore(url: dir.appendingPathComponent("targets.json"))
        try store.save([])
        let mode = (try FileManager.default.attributesOfItem(atPath: store.url.path)[.posixPermissions] as! NSNumber).intValue
        XCTAssertEqual(mode & 0o777, 0o600)
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: dir.path).contains { $0.contains(".tmp-") })
        // A symlinked targets.json is refused, and the file it points at is left untouched.
        let other = dir.appendingPathComponent("elsewhere.json"); try Data("keep".utf8).write(to: other)
        try FileManager.default.removeItem(at: store.url)
        try FileManager.default.createSymbolicLink(at: store.url, withDestinationURL: other)
        XCTAssertThrowsError(try store.save([]))
        XCTAssertEqual(try String(contentsOf: other), "keep")
        XCTAssertNotNil(try? FileManager.default.destinationOfSymbolicLink(atPath: store.url.path), "the link itself is not replaced")
    }
}
