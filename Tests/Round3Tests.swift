import XCTest
/// 0.8.0 review round 3: targets.json file-type guards, backup pruning, strict service decode, HP-UX, DER/combined overrides.
final class Round3Tests: XCTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    var dirs: [URL] = []
    func tmp() throws -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("r3-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true); dirs.append(d); return d
    }
    override func tearDown() { for d in dirs { try? FileManager.default.removeItem(at: d) }; dirs = [] }
    func regularBackups(_ d: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: d.path).filter { n in
            var st = stat(); return n.hasPrefix("targets.json.bak-") && lstat(d.appendingPathComponent(n).path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG
        }
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
        XCTAssertEqual(try regularBackups(d).count, 5)
    }
    func testSameSecondBackupsSortAndPrune() throws {
        let d = try tmp(), store = TargetStore(url: d.appendingPathComponent("targets.json"))
        try store.save(one); let now = Date()
        var made: [URL] = []
        for _ in 0..<12 { made.append(try XCTUnwrap(try store.backup(now: now))) }
        XCTAssertEqual(made.map(\.lastPathComponent), made.map(\.lastPathComponent).sorted())
        TargetLibrary.pruneBackups(store)
        XCTAssertEqual(Set(try regularBackups(d)), Set(made.suffix(5).map(\.lastPathComponent)))
    }
    func testSymlinkedParentRefused() throws {
        let d = try tmp(), real = d.appendingPathComponent("real"), link = d.appendingPathComponent("link")
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        try JSONEncoder().encode(one).write(to: real.appendingPathComponent("targets.json"))
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        XCTAssertThrowsError(try TargetStore(url: link.appendingPathComponent("targets.json")).load())
    }
    func testOddOverrideFilesGetSpecificErrors() throws {
        let d = try tmp()
        func w(_ n: String, _ s: String) throws -> URL { let u = d.appendingPathComponent(n); try Data(s.utf8).write(to: u); return u }
        let cases: [(URL, String)] = [
            (try w("empty", ""), "empty"),
            (try w("req.csr", "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n"), "signing request"),
            (try w("pub.pem", "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"), "public key"),
            (try w("junk.bin", "not a key"), "not a PEM or DER"),
        ]
        for (u, want) in cases {
            XCTAssertThrowsError(try Munki.classifyOverrides([u]), u.lastPathComponent) { XCTAssertTrue("\($0)".contains(want), "\(u.lastPathComponent): \($0)") }
        }
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

/// App commit/delete go through TargetLibrary.upsert/delete: save first, change `targets` only on success.
final class TargetLibraryMutationTests: XCTestCase {
    func testUpsertAndDeleteLeaveTargetsUnchangedOnFailure() throws {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("lib-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true); defer { try? FileManager.default.removeItem(at: d) }
        var lib = TargetLibrary(store: TargetStore(url: d.appendingPathComponent("targets.json")))
        let a = Target(name: "a", host: "a.example.test", service: .https)
        try lib.upsert(a); XCTAssertEqual(lib.targets, [a])
        var a2 = a; a2.name = "renamed"; try lib.upsert(a2); XCTAssertEqual(lib.targets.map(\.name), ["renamed"])
        var bad = a; bad.host = "not a host!"; XCTAssertThrowsError(try lib.upsert(bad)); XCTAssertEqual(lib.targets, [a2])
        // Make the save fail: replace targets.json with a directory.
        try FileManager.default.removeItem(at: d.appendingPathComponent("targets.json"))
        try FileManager.default.createDirectory(at: d.appendingPathComponent("targets.json"), withIntermediateDirectories: true)
        XCTAssertThrowsError(try lib.upsert(Target(name: "b", host: "b.example.test", service: .https))); XCTAssertEqual(lib.targets, [a2])
        XCTAssertThrowsError(try lib.delete(id: a2.id)); XCTAssertEqual(lib.targets, [a2])
        try FileManager.default.removeItem(at: d.appendingPathComponent("targets.json"))
        try lib.delete(id: a2.id); XCTAssertEqual(lib.targets, [])
        XCTAssertEqual(try TargetStore(url: d.appendingPathComponent("targets.json")).load(), [])
    }
}
