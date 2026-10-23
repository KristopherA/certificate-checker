import XCTest

/// Docker registry / Logstash Beats / Elasticsearch / Beats client mTLS pair (0.7.0). SYNTHETIC-* fixtures; live tests use the loopback fake server only.
final class StackTests: PinnedTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func sev(_ f: [Finding], _ id: String) -> Severity? { f.first { $0.id == id }?.severity }
    func chain(_ n: String) throws -> [Certificate] { try PEM.blocks(String(decoding: try Data(contentsOf: fx(n)), as: UTF8.self)).map { try Certificate(der: $0.der) } }
    let untrusted = [Finding("trust", .fail, .trust, "Not trusted")]

    func testServiceDefaults() {
        XCTAssertEqual(Service.dockerRegistry.defaultPort, 443); XCTAssertEqual(Service.logstashBeats.defaultPort, 5044); XCTAssertEqual(Service.elasticsearch.defaultPort, 9200)
        XCTAssertEqual(Service.dockerRegistry.defaultPlatform, .dockerRegistry); XCTAssertEqual(Service.elasticsearch.defaultPlatform, .elasticStack)
        for s in [Service.dockerRegistry, .logstashBeats, .elasticsearch] {
            XCTAssertTrue(s.isStack); XCTAssertFalse(s.isAppliance); XCTAssertFalse(s.usesUpgrade); XCTAssertFalse(Probe.allowsTrustNetworkFetch(s), s.rawValue)
        }
        XCTAssertFalse(Service.https.isStack); XCTAssertTrue(Probe.allowsTrustNetworkFetch(.https))
    }
    func testRegistryRequestHasNoCredentials() {
        let r = RegistryAPI.request(host: "registry.example.test", port: 5000)
        XCTAssertTrue(r.hasPrefix("GET /v2/ HTTP/1.1\r\nHost: registry.example.test:5000\r\n")); XCTAssertTrue(r.hasSuffix("\r\n\r\n"))
        XCTAssertFalse(r.lowercased().contains("authorization")); XCTAssertFalse(r.lowercased().contains("cookie"))
        XCTAssertTrue(RegistryAPI.request(host: "registry.example.test", port: 443).contains("Host: registry.example.test\r\n"))
        XCTAssertTrue(RegistryAPI.request(host: "::1", port: 5000).contains("Host: [::1]:5000"))
    }
    func testRegistryParseAndFindings() {
        let r401 = RegistryAPI.parse(["HTTP/1.1 401 Unauthorized", "Docker-Distribution-Api-Version: registry/2.0", "WWW-Authenticate: Bearer realm=\"x\""])
        XCTAssertEqual(r401, .init(status: 401, apiVersion: "registry/2.0", schemes: ["Bearer"]))
        XCTAssertEqual(RegistryAPI.findings(r401).first?.severity, .pass)
        let basic = RegistryAPI.findings(RegistryAPI.parse(["HTTP/1.1 401 Unauthorized", "WWW-Authenticate: Basic realm=\"r\""])).first!
        XCTAssertEqual(basic.severity, .pass); XCTAssertTrue(basic.detail.contains("Basic"))
        XCTAssertEqual(RegistryAPI.findings(RegistryAPI.parse(["HTTP/1.1 200 OK", "Docker-Distribution-Api-Version: registry/2.0"])).first?.severity, .warning)
        XCTAssertTrue(RegistryAPI.findings(RegistryAPI.parse(["HTTP/1.1 200 OK"])).first!.title.contains("anonymous"))
        XCTAssertTrue(RegistryAPI.findings(RegistryAPI.parse(["HTTP/1.1 404 Not Found"])).first!.title.contains("not a Docker registry"))
        XCTAssertNil(RegistryAPI.parse(["SSH-2.0-x"])); XCTAssertEqual(RegistryAPI.findings(nil).first?.severity, .warning)
        XCTAssertEqual(RegistryAPI.findings(nil, error: "timed out").first?.severity, .info)
        for f in RegistryAPI.findings(r401) { XCTAssertEqual(f.topic, .stack); XCTAssertFalse(StackAdvisor.guidance(for: f, target: nil).isEmpty) }
    }
    func testAdjustNotesAndElasticAutoCA() throws {
        let t = Target(name: "", host: "host.example.test", service: .elasticsearch)
        let auto = Stack.adjust(untrusted, chain: try chain("SYNTHETIC-es-auto.pem"), target: t)
        XCTAssertEqual(sev(auto, "es-autoca"), .warning); XCTAssertNil(sev(auto, "es-tls"))
        let normal = Stack.adjust(untrusted, chain: try chain("SYNTHETIC-es-server.pem"), target: t)
        XCTAssertEqual(sev(normal, "es-tls"), .info); XCTAssertNil(sev(normal, "es-autoca"))
        XCTAssertNotNil(sev(Stack.adjust([], chain: try chain("SYNTHETIC-registry-server.pem"), target: Target(name: "", host: "host.example.test", port: 5000, service: .dockerRegistry)), "reg-tls"))
        XCTAssertTrue(Stack.adjust([], chain: try chain("SYNTHETIC-registry-server.pem"), target: Target(name: "", host: "host.example.test", port: 5000, service: .dockerRegistry)).first!.detail.contains("certs.d/host.example.test:5000/ca.crt"))
        XCTAssertEqual(Stack.adjust(untrusted, chain: try chain("SYNTHETIC-es-server.pem"), target: Target(name: "", host: "h.example.test", service: .https)), untrusted)
        XCTAssertNotNil(Stack.handshakeFailureNote(Target(name: "", host: "h.example.test", service: .logstashBeats)))
        XCTAssertNil(Stack.handshakeFailureNote(Target(name: "", host: "h.example.test", service: .dockerRegistry)))
    }
    func testSuppliedCA() throws {
        let c = try chain("SYNTHETIC-logstash-server.pem"), ca = try chain("SYNTHETIC-stack-ca.pem"), other = try chain("SYNTHETIC-other-ca.pem")
        let ok = Stack.suppliedCA(untrusted, chain: c, ca: ca, hostname: "logstash.example.test")
        XCTAssertEqual(sev(ok, "ca-chain"), .pass); XCTAssertEqual(sev(ok, "trust"), .info, "clients use the supplied CA, not the macOS store")
        let leafOnly = Stack.suppliedCA(untrusted, chain: [c[0]], ca: ca, hostname: "logstash.example.test")
        XCTAssertEqual(sev(leafOnly, "ca-chain"), .pass, "the CA file completes a leaf-only chain")
        let bad = Stack.suppliedCA(untrusted, chain: c, ca: other, hostname: "logstash.example.test")
        XCTAssertEqual(sev(bad, "ca-chain"), .fail); XCTAssertEqual(sev(bad, "trust"), .fail)
        XCTAssertEqual(Stack.suppliedCA(untrusted, chain: c, ca: [], hostname: "logstash.example.test"), untrusted)
        XCTAssertEqual(try Stack.loadCA([fx("SYNTHETIC-stack-ca.pem")]).count, 1)
        XCTAssertThrowsError(try Stack.loadCA([fx("SYNTHETIC-beats-client.key")]))
    }
    func testSuppliedCADowngradesOnlyAnUntrustedRoot() throws {
        let c = try chain("SYNTHETIC-logstash-server.pem"), ca = try chain("SYNTHETIC-stack-ca.pem")
        let expired = Stack.suppliedCA(untrusted, chain: c, ca: ca, hostname: "logstash.example.test", now: c[0].notAfter.addingTimeInterval(86_400))
        XCTAssertEqual(sev(expired, "trust"), .fail, "an expired leaf under the supplied CA still fails")
        let wrongHost = Stack.suppliedCA(untrusted, chain: c, ca: ca, hostname: "wrong.example.test")
        XCTAssertEqual(sev(wrongHost, "ca-chain"), .pass); XCTAssertEqual(sev(wrongHost, "trust"), .fail, "a hostname mismatch still fails")
        XCTAssertEqual(sev(Stack.suppliedCA(untrusted, chain: c, ca: ca, hostname: nil), "trust"), .fail, "no hostname, no downgrade")
        let forged = Stack.suppliedCA(untrusted, chain: Array(try chain("SYNTHETIC-beats-otherca.pem").prefix(1)) + ca, ca: ca, hostname: "beats03.example.test")
        XCTAssertEqual(sev(forged, "ca-chain"), .fail); XCTAssertEqual(sev(forged, "trust"), .fail, "a leaf not signed by the supplied CA still fails")
    }
    func testNonCACertificateInCAFileWarns() throws {
        let c = try chain("SYNTHETIC-logstash-server.pem"), ca = try chain("SYNTHETIC-stack-ca.pem")
        let r = Stack.suppliedCA(untrusted, chain: c, ca: ca + [c[0]], hostname: "logstash.example.test")
        XCTAssertEqual(r.filter { $0.id.hasPrefix("ca-nonca-") }.count, 1)
        XCTAssertTrue(Stack.suppliedCA(untrusted, chain: c, ca: ca, hostname: "logstash.example.test").allSatisfy { !$0.id.hasPrefix("ca-nonca-") })
        XCTAssertEqual(Stack.nonCAWarnings(ca + [c[0]]).first?.severity, .warning)
    }
    func testMTLSPairAnyEKUFailsWithReason() {
        let r = MTLSPair.inspect([fx("SYNTHETIC-beats-anyeku.pem"), fx("SYNTHETIC-beats-anyeku.key")], ca: [])
        let f = r.findings.first { $0.id == "mtls-eku" }
        XCTAssertEqual(f?.severity, .fail); XCTAssertTrue(f?.detail.contains("anyExtendedKeyUsage") == true); XCTAssertTrue(f?.detail.contains("clientAuth") == true)
    }
    func testMTLSPairGood() {
        let r = MTLSPair.inspect([fx("SYNTHETIC-beats-client.pem"), fx("SYNTHETIC-beats-client.key")], ca: [fx("SYNTHETIC-stack-ca.pem")])
        XCTAssertFalse(r.findings.contains { $0.severity == .fail }, r.findings.map { "\($0.id) \($0.title)" }.joined(separator: "\n"))
        XCTAssertEqual(sev(r.findings, "mtls-eku"), .pass); XCTAssertEqual(sev(r.findings, "mtls-key-0"), .pass); XCTAssertEqual(sev(r.findings, "mtls-ca"), .pass)
        XCTAssertEqual(sev(r.findings, "mtls-handshake"), .info)
        XCTAssertEqual(r.chain.count, 2); XCTAssertTrue(r.chain[0].subject.text.contains("beats01.example.test"))
        let text = r.findings.map { $0.title + $0.detail }.joined()
        XCTAssertFalse(text.contains("PRIVATE KEY")); XCTAssertFalse(text.contains("MII"))
    }
    func testMTLSPairProblems() {
        let eku = MTLSPair.inspect([fx("SYNTHETIC-beats-serveronly.pem"), fx("SYNTHETIC-beats-serveronly.key")], ca: [fx("SYNTHETIC-stack-ca.pem")])
        XCTAssertEqual(sev(eku.findings, "mtls-eku"), .fail)
        let mismatch = MTLSPair.inspect([fx("SYNTHETIC-beats-client.pem"), fx("SYNTHETIC-beats-serveronly.key")], ca: [fx("SYNTHETIC-stack-ca.pem")])
        XCTAssertEqual(sev(mismatch.findings, "mtls-key-0"), .fail)
        let otherCA = MTLSPair.inspect([fx("SYNTHETIC-beats-otherca.pem"), fx("SYNTHETIC-beats-otherca.key")], ca: [fx("SYNTHETIC-stack-ca.pem")])
        XCTAssertEqual(sev(otherCA.findings, "mtls-ca"), .fail)
        let noCA = MTLSPair.inspect([fx("SYNTHETIC-beats-client.pem")], ca: [])
        XCTAssertEqual(sev(noCA.findings, "mtls-ca"), .warning); XCTAssertEqual(sev(noCA.findings, "mtls-key"), .warning)
        let missing = MTLSPair.inspect([fx("does-not-exist.pem")], ca: [])
        XCTAssertTrue(missing.findings.contains { $0.severity == .fail })
        for f in eku.findings where f.severity == .fail { XCTAssertFalse(StackAdvisor.guidance(for: f, target: nil).isEmpty, f.id) }
    }
    func testGuidanceIsGenericAndCopyOnly() {
        let all = [StackAdvisor.registry(host: "registry.example.test", port: 5000), StackAdvisor.logstash(), StackAdvisor.filebeat(), StackAdvisor.filebeat(output: "elasticsearch"), StackAdvisor.elasticsearch()]
        let text = all.flatMap { $0.steps + $0.commands }.joined(separator: "\n")
        XCTAssertTrue(text.contains("/etc/docker/certs.d/registry.example.test:5000/ca.crt")); XCTAssertTrue(text.contains("ssl.certificate_authorities"))
        XCTAssertTrue(text.contains("ssl_client_authentication")); XCTAssertTrue(text.contains("xpack.security.http.ssl"))
        XCTAssertFalse(text.contains("BEGIN")); XCTAssertNotNil(Advisor.replace(.dockerRegistry, host: "registry.example.test", reason: .trust, service: .dockerRegistry).title)
    }
    func testStackForm() {
        var f = StackForm(); XCTAssertFalse(f.canRun); f.host = " registry.example.test "; f.checkV2 = true
        XCTAssertTrue(f.runsV2); XCTAssertEqual(f.target.host, "registry.example.test"); XCTAssertEqual(f.target.port, 443)
        f.port = "5000"; XCTAssertEqual(f.target.port, 5000); XCTAssertNoThrow(try f.target.validate())
        f.select(.logstashBeats); XCTAssertFalse(f.runsV2); XCTAssertEqual(f.target.port, 5044); XCTAssertEqual(f.target.platform, .elasticStack)
    }

    // MARK: Loopback fake server
    func server(_ mode: String, chain: String = "SYNTHETIC-registry-server.pem", key: String = "SYNTHETIC-registry-server.key") throws -> (Process, Int) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = [fx("tls_server.py").path, mode, fx(chain).path, fx(key).path]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        try p.run()
        guard let port = Int(String(decoding: out.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else { p.terminate(); throw XCTSkip("test server did not start") }
        return (p, port)
    }
    func testRegistryLoopback() async throws {
        for (mode, want) in [("registry-401", Severity.pass), ("registry-200", .warning), ("registry-404", .warning)] {
            let (p, port) = try server(mode); defer { p.terminate() }
            let t = Target(name: mode, host: "127.0.0.1", port: port, service: .dockerRegistry, sni: "registry.example.test")
            var r = await Probe.run(t, timeout: 10, registryAPI: true)
            XCTAssertNil(r.error, "\(mode) \(r.error ?? "") \(r.transcript)"); XCTAssertEqual(r.chain.count, 2, mode)
            XCTAssertEqual(sev(r.findings, "reg-v2"), want, "\(mode): \(r.findings.map(\.id)) \(r.transcript)")
            XCTAssertEqual(sev(r.findings, "host"), .pass, mode)
            r.findings = Stack.suppliedCA(r.findings, chain: r.chain, ca: try chain("SYNTHETIC-stack-ca.pem"), hostname: t.verifyName)
            XCTAssertEqual(sev(r.findings, "ca-chain"), .pass, mode)
        }
    }
    func testRegistryWithoutOptInSendsNothing() async throws {
        let (p, port) = try server("registry-401"); defer { p.terminate() }
        let r = await Probe.run(Target(name: "", host: "127.0.0.1", port: port, service: .dockerRegistry, sni: "registry.example.test"), timeout: 10)
        XCTAssertNil(r.error); XCTAssertNil(sev(r.findings, "reg-v2")); XCTAssertFalse(r.transcript.contains { $0.contains("GET /v2/") })
        XCTAssertEqual(sev(r.findings, "reg-tls"), .info)
    }
    func testBeatsLoopback() async throws {
        let (p, port) = try server("tls", chain: "SYNTHETIC-logstash-server.pem", key: "SYNTHETIC-logstash-server.key"); defer { p.terminate() }
        let r = await Probe.run(Target(name: "", host: "127.0.0.1", port: port, service: .logstashBeats, sni: "host.example.test"), timeout: 10)
        XCTAssertNil(r.error, r.error ?? ""); XCTAssertEqual(sev(r.findings, "beats-tls"), .info); XCTAssertEqual(r.chain.count, 2)
    }
}
