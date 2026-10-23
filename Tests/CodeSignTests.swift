import XCTest
/// Code signing (0.9.0). Uses system binaries and a temporary ad-hoc signed copy; pkgutil output is parsed from text.
final class CodeSignTests: PinnedTestCase {
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }
    func testAppleSignedBinary() throws {
        let i = try CodeSign.info(URL(fileURLWithPath: "/bin/ls"))
        XCTAssertTrue(i.signed); XCTAssertTrue(i.valid); XCTAssertFalse(i.adHoc)
        XCTAssertEqual(sev(CodeSign.inspect(i), "cs-valid"), .pass)
    }
    func testAdHocAndTampered() throws {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("cs-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: d) }
        let bin = d.appendingPathComponent("tool"); try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: bin.path)
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/codesign"); p.arguments = ["-f", "-s", "-", bin.path]
        p.standardError = Pipe(); try p.run(); p.waitUntilExit(); XCTAssertEqual(p.terminationStatus, 0)
        var f = CodeSign.inspect(try CodeSign.info(bin))
        XCTAssertEqual(sev(f, "cs-adhoc"), .warning); XCTAssertEqual(sev(f, "cs-valid"), .pass)
        let h = try FileHandle(forWritingTo: bin); try h.seek(toOffset: 0x2000); try h.write(contentsOf: Data([0xDE, 0xAD])); try h.close()
        f = CodeSign.inspect(try CodeSign.info(bin)); XCTAssertEqual(sev(f, "cs-valid"), .fail)
    }
    func testUnsigned() throws {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("cs-u-" + UUID().uuidString + ".sh")
        try Data("#!/bin/sh\n".utf8).write(to: d); defer { try? FileManager.default.removeItem(at: d) }
        XCTAssertEqual(sev(CodeSign.inspect(try CodeSign.info(d)), "cs-signed"), .fail)
    }
    func testPkgutilParse() {
        let ok = CodeSign.parsePkgutil("Package \"package.pkg\":\n   Status: signed by a developer certificate issued by Apple for distribution\n   Notarization: trusted by the Apple notary service\n   Signed with a trusted timestamp on: 2026-01-02 03:04:05 +0000\n")
        XCTAssertTrue(ok.valid); XCTAssertNotNil(ok.timestamp)
        let none = CodeSign.parsePkgutil("Package \"package.pkg\":\n   Status: no signature\n")
        XCTAssertFalse(none.signed); XCTAssertEqual(sev(CodeSign.inspect(none), "cs-signed"), .fail)
        let bad = CodeSign.parsePkgutil("Package \"package.pkg\":\n   Status: signed by a certificate that has since expired\n")
        XCTAssertTrue(bad.signed); XCTAssertFalse(bad.valid); XCTAssertEqual(sev(CodeSign.inspect(bad), "cs-valid"), .fail)
    }
}
