import XCTest
/// 0.8.0 review round 3: targets.json file-type guards, backup pruning, strict service decode, HP-UX, DER/combined overrides.
final class Round3Tests: XCTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func tmp() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("r3-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true); return d
    }
    let one = [Target(name: "a", host: "a.example.test", service: .https)]

    func testSymlinkedTargetsRefused() throws {
        let d = try tmp(), real = d.appendingPathComponent("real.json"), link = d.appendingPathComponent("targets.json")
        try JSONEncoder().encode(one).write(to: real)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        let store = TargetStore(url: link)
        XCTAssertThrowsError(try store.load()); XCTAssertThrowsError(try store.backup()); XCTAssertThrowsError(try store.save(one))
        var lib = TargetLibrary(store: store)
        XCTAssertTrue(lib.savesBlocked); XCTAssertThrowsError(try lib.save(one))
        XCTAssertEqual(try JSONDecoder().decode([Target].self, from: Data(contentsOf: real)), one)
    }
    func testPruneSkipsDirectories() throws {
        let d = try tmp(), store = TargetStore(url: d.appendingPathComponent("targets.json"))
        let trap = d.appendingPathComponent("targets.json.bak-00000000-000000")
        try FileManager.default.createDirectory(at: trap, withIntermediateDirectories: true)
        try Data("keep".utf8).write(to: trap.appendingPathComponent("inner"))
        var lib = TargetLibrary(store: store)
        for i in 0..<8 { try lib.save([Target(name: "t\(i)", host: "h\(i).example.test", service: .https)]); Thread.sleep(forTimeInterval: 0.001) }
        var isDir: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: trap.path, isDirectory: &isDir)); XCTAssertTrue(isDir.boolValue)
    }
    func testMissingServiceFailsDecode() {
        XCTAssertThrowsError(try JSONDecoder().decode([Target].self, from: Data(#"[{"host":"x.example.test"}]"#.utf8)))
    }
    func testHPUXNotHPDefault() {
        XCTAssertFalse(Vendor.isHPName("HP-UX")); XCTAssertFalse(Vendor.isHPName("hp-ux.example.test"))
        XCTAssertTrue(Vendor.isHPName("HP 1A2B3C"))
    }
    func testDEROverridesAndCombinedPEM() throws {
        let d = try tmp()
        let keyPEM = String(decoding: try Data(contentsOf: fx("SYNTHETIC-munki-client.key")), as: UTF8.self)
        let certPEM = String(decoding: try Data(contentsOf: fx("SYNTHETIC-munki-client.pem")), as: UTF8.self)
        let keyDER = d.appendingPathComponent("client.key.der"), certDER = d.appendingPathComponent("client.cer")
        try Data(PEM.blocks(keyPEM)[0].der).write(to: keyDER); try Data(PEM.blocks(certPEM)[0].der).write(to: certDER)
        let o = try Munki.classifyOverrides([keyDER, certDER])
        XCTAssertEqual(o.key, keyDER); XCTAssertEqual(o.cert, certDER)
        let both = d.appendingPathComponent("both.pem"); try Data((certPEM + keyPEM).utf8).write(to: both)
        XCTAssertThrowsError(try Munki.classifyOverrides([both])) { XCTAssertTrue("\($0)".contains("both") || ($0 as? LocalizedError)?.errorDescription?.contains("both") == true) }
    }
}
