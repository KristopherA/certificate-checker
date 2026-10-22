import XCTest
import CryptoKit

final class WireGuardTests: XCTestCase {
    func fx(_ n: String) -> URL { CertificateCheckerTests.fixtures.appendingPathComponent(n) }
    func privateKey(in file: String) throws -> String {
        let text = try String(contentsOf: fx(file))
        if file.hasSuffix(".xml") { return String(text.components(separatedBy: "<privatekey>")[1].prefix(44)) }
        return text.split(separator: "\n").first { $0.hasPrefix("PrivateKey") }!.split(separator: "=", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)
    }
    func ids(_ f: [Finding], _ s: Severity) -> [String] { f.filter { $0.severity == s }.map(\.id) }

    func testKeyFormat() {
        let k = Curve25519.KeyAgreement.PrivateKey()
        let b64 = k.rawRepresentation.base64EncodedString()
        XCTAssertEqual(WGKey.decode(b64).0, .valid)
        XCTAssertEqual(WGKey.decode("not-a-key").0, .notBase64)
        XCTAssertEqual(WGKey.decode(Data(count: 16).base64EncodedString()).0, .wrongLength(16))
        XCTAssertEqual(WGKey.publicKey(fromPrivate: b64).1, k.publicKey.rawRepresentation.base64EncodedString())
    }
    func testGoodPairIsConsistent() throws {
        let r = WGCheck.inspect([fx("wg-server.conf"), fx("wg-client.conf")])
        XCTAssertEqual(r.configs.count, 2)
        XCTAssertEqual(r.configs[0].peers.map(\.name), ["laptop", "phone"])
        XCTAssertTrue(ids(r.findings, .fail).isEmpty, "\(r.findings)")
        XCTAssertTrue(r.findings.contains { $0.id == "x-0-1" && $0.severity == .pass })
        XCTAssertTrue(r.findings.contains { $0.id == "wg0-key-priv" && $0.severity == .pass })
    }
    func testBadConfigFindings() throws {
        let f = WGCheck.inspect([fx("wg-bad.conf")]).findings
        let fails = Set(ids(f, .fail))
        for expected in ["wg0-peer0-psk", "wg0-peer0-endpoint", "wg0-peer1-dup", "wg0-peer1-endpoint", "wg0-peer1-allowed-300.1.1.1/32", "wg0-peer2-self", "wg0-peer1-overlap-198.51.100.0/24-0-198.51.100.0/24"] {
            XCTAssertTrue(fails.contains(expected), "missing \(expected) in \(fails.sorted())")
        }
        XCTAssertTrue(ids(f, .warning).contains("wg0-peer2-overlap-198.51.100.5/32-0-198.51.100.0/24"), "\(f.map(\.id))")
    }
    func testEndpointSyntax() {
        XCTAssertNil(WGCheck.endpointProblem("vpn.example:51820"))
        XCTAssertNil(WGCheck.endpointProblem("[2001:db8::1]:51820"))
        XCTAssertNil(WGCheck.endpointProblem("203.0.113.5:443"))
        XCTAssertNotNil(WGCheck.endpointProblem("vpn.example"))
        XCTAssertNotNil(WGCheck.endpointProblem("2001:db8::1:51820"))
        XCTAssertNotNil(WGCheck.endpointProblem("vpn.example:0"))
        XCTAssertNotNil(WGCheck.endpointProblem("[2001:db8::1]51820"))
        XCTAssertNotNil(WGCheck.endpointProblem("bad host;x:51820"))
    }
    func testCIDR() {
        XCTAssertTrue(CIDR("10.0.0.0/8")!.overlaps(CIDR("10.1.2.3/32")!))
        XCTAssertFalse(CIDR("10.0.0.0/24")!.overlaps(CIDR("10.0.1.0/24")!))
        XCTAssertFalse(CIDR("10.0.0.0/8")!.overlaps(CIDR("fd00::/8")!))
        XCTAssertTrue(CIDR("0.0.0.0/0")!.sameNetwork(CIDR("0.0.0.0/0")!))
        XCTAssertNil(CIDR("10.0.0.0/33")); XCTAssertNil(CIDR("bogus"))
    }
    func testPfSenseExport() throws {
        let r = WGCheck.inspect([fx("pfsense-config.xml")])
        XCTAssertEqual(r.configs.count, 1)
        XCTAssertEqual(r.configs[0].peers.map(\.name), ["laptop", "branch"])
        XCTAssertEqual(r.configs[0].peers[1].endpoint, "branch.example.internal:51820")
        // Fixture states the wrong public key for the tunnel, and branch's 198.51.100.0/24 contains laptop's /32.
        XCTAssertTrue(r.findings.contains { $0.id == "wg0-key-pub" && $0.severity == .fail }, "\(r.findings)")
        XCTAssertTrue(r.findings.contains { $0.id.hasPrefix("wg0-peer1-overlap") && $0.severity == .warning })
    }
    func testExpectedPublicKey() throws {
        let c = WGParse.wgQuick(try String(contentsOf: fx("wg-client.conf")), name: "c")
        XCTAssertTrue(WGCheck.evaluate([c], expectedPublicKey: c.derivedPublicKey).contains { $0.id == "wg0-key-expected" && $0.severity == .pass })
        XCTAssertTrue(WGCheck.evaluate([c], expectedPublicKey: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation.base64EncodedString()).contains { $0.id == "wg0-key-expected" && $0.severity == .fail })
    }
    func testCrossFileMismatch() throws {
        var server = WGParse.wgQuick(try String(contentsOf: fx("wg-server.conf")), name: "server")
        let client = WGParse.wgQuick(try String(contentsOf: fx("wg-client.conf")), name: "client")
        server.peers[0].publicKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
        XCTAssertTrue(WGCheck.evaluate([server, client]).contains { $0.id == "x-0-1" && $0.severity == .fail })
    }
    /// Private keys must never surface in findings, guidance, parsed models or their descriptions.
    func testPrivateKeysNeverExposed() throws {
        for file in ["wg-server.conf", "wg-client.conf", "wg-bad.conf", "pfsense-config.xml"] {
            let secret = try privateKey(in: file)
            XCTAssertEqual(secret.count, 44)
            let raw = Data(base64Encoded: secret)!
            let r = WGCheck.inspect([fx(file)])
            var text = r.findings.map { "\($0.title) \($0.detail)" }.joined(separator: "\n")
            text += String(describing: r.configs) + String(reflecting: r.configs)
            for f in r.findings { for p in [Platform.pfSense, .generic, .macOS] { for g in WGAdvisor.guidance(for: f, platform: p) { text += g.steps.joined() + g.commands.joined() } } }
            XCTAssertFalse(text.contains(secret), "private key leaked for \(file)")
            XCTAssertFalse(text.contains(raw.map { String(format: "%02x", $0) }.joined()), "hex private key leaked for \(file)")
            XCTAssertFalse(text.contains(String(secret.prefix(16))), "private key prefix leaked for \(file)")
            XCTAssertFalse(text.lowercased().contains("showconf"), "guidance must not suggest wg showconf")
        }
    }
    func testGuidanceKindsComeFromFindingField() throws {
        let f = WGCheck.inspect([fx("wg-bad.conf")]).findings
        XCTAssertEqual(f.first { $0.id == "wg0-peer0-psk" }.map(WGAdvisor.kind), .peer)
        XCTAssertEqual(f.first { $0.id == "wg0-peer0-endpoint" }.map(WGAdvisor.kind), .endpoint)
        XCTAssertEqual(f.first { $0.id.hasPrefix("wg0-peer1-overlap") }.map(WGAdvisor.kind), .allowed)
        XCTAssertEqual(f.first { $0.id == "wg0-key-priv" }.map(WGAdvisor.kind), .key)
        XCTAssertTrue(f.filter { $0.topic == .wireguard }.allSatisfy { !$0.kind.isEmpty })
        for p in [Platform.pfSense, .generic, .macOS] { XCTAssertFalse(WGAdvisor.guidance(for: Finding("k", .fail, .wireguard, "t", kind: "key"), platform: p).isEmpty) }
        let linux = WGAdvisor.guidance(for: Finding("k", .fail, .wireguard, "t", kind: "key"), platform: .generic).flatMap(\.commands)
        XCTAssertTrue(linux.contains("sudo sh -c 'umask 077; mkdir -p /etc/wireguard && set -C && wg genkey > /etc/wireguard/wg0.key.new && wg pubkey < /etc/wireguard/wg0.key.new'"))
        XCTAssertTrue(linux.contains("sudo bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'"))
        let mac = WGAdvisor.guidance(for: Finding("k", .fail, .wireguard, "t", kind: "key"), platform: .macOS)
        XCTAssertFalse(mac.flatMap(\.commands).joined().contains("rm -P")); XCTAssertFalse(mac.flatMap(\.commands).joined().contains("wg show"))
        XCTAssertTrue(WGAdvisor.guidance(for: Finding("k", .fail, .wireguard, "t", kind: "peer"), platform: .pfSense)[0].steps.joined().contains("Diagnostics › Command Prompt"))
    }
    // MARK: review follow-ups
    static func key() -> (priv: String, pub: String) { let k = Curve25519.KeyAgreement.PrivateKey(); return (k.rawRepresentation.base64EncodedString(), k.publicKey.rawRepresentation.base64EncodedString()) }
    func peerConf(_ peers: [(String, String, [String])], address: String = "198.51.100.1/24") -> WGConfig {
        var c = WGConfig(name: "t", source: "test"); let k = Self.key(); c.privateKeyStatus = .valid; c.derivedPublicKey = k.pub; c.addresses = [address]
        c.peers = peers.map { WGPeer(name: $0.0, publicKey: $0.1, allowedIPs: $0.2) }; return c
    }
    func xml(root: String = "pfsense", _ body: String) -> Data {
        let inner = "<wireguard>\(body)</wireguard>"
        return Data((root == "wireguard" ? inner : "<?xml version=\"1.0\"?><pfsense><installedpackages>\(inner)</installedpackages></pfsense>").utf8)
    }
    func tunnel(_ name: String, _ priv: String, enabled: String = "yes") -> String { "<tunnels><item><name>\(name)</name><enabled>\(enabled)</enabled><privatekey>\(priv)</privatekey></item></tunnels>" }
    func peer(_ tun: String, _ descr: String, _ pub: String, enabled: String = "yes", extra: String = "") -> String {
        "<item><enabled>\(enabled)</enabled><tun>\(tun)</tun><descr>\(descr)</descr><publickey>\(pub)</publickey>\(extra)</item>"
    }

    func testCIDRSlashInputsDoNotTrap() {
        for bad in ["/", "/24", "10.0.0.0/", "10.0.0.0/+8", "10.0.0.0/8/8", "", " "] { XCTAssertNil(CIDR(bad), bad) }
        let f = WGCheck.evaluate([peerConf([("a", Self.key().pub, ["/"]), ("b", Self.key().pub, ["/24"])])])
        XCTAssertEqual(f.filter { $0.id.contains("-allowed-") && $0.severity == .fail }.count, 2)
    }
    func testDisabledAndUnassignedEntries() throws {
        let k = Self.key(), p = Self.key()
        let body = "<tunnels><item><name>tun_wg0</name><enabled>yes</enabled><privatekey>\(k.priv)</privatekey></item><item><name>tun_wg1</name><enabled>no</enabled><privatekey>\(Self.key().priv)</privatekey></item></tunnels>"
            + "<peers>" + peer("tun_wg0", "live", p.pub, extra: "<allowedips><row><address>198.51.100.2</address><mask>32</mask></row></allowedips>") + peer("tun_wg0", "off", Self.key().pub, enabled: "no") + peer("unassigned", "loose", Self.key().pub) + peer("tun_wg1", "ondisabled", Self.key().pub) + "</peers>"
        let r = try WGParse.pfSense(xml(body), name: "x")
        XCTAssertEqual(r.configs.count, 1); XCTAssertEqual(r.configs[0].peers.map(\.name), ["live"])
        let ids = r.notes.map(\.id)
        XCTAssertTrue(ids.contains("wg-disabled-tun_wg1")); XCTAssertTrue(ids.contains("wg-disabled-peer-1")); XCTAssertTrue(ids.contains("wg-unassigned-2"))
        XCTAssertTrue(r.notes.allSatisfy { $0.severity == .info })
    }
    func testMultipleTunnelsAndWireguardRoot() throws {
        let a = Self.key(), b = Self.key()
        let body = "<tunnels><item><name>tun_wg0</name><enabled>yes</enabled><privatekey>\(a.priv)</privatekey></item><item><name>tun_wg1</name><enabled>yes</enabled><privatekey>\(b.priv)</privatekey></item></tunnels><peers>" + peer("tun_wg0", "p0", Self.key().pub) + peer("tun_wg1", "p1", Self.key().pub) + peer("tun_wg1", "p2", Self.key().pub) + "</peers>"
        for root in ["pfsense", "wireguard"] {
            let r = try WGParse.load(name: "x", data: xml(root: root, body))
            XCTAssertEqual(r.configs.map(\.peers.count), [1, 2], root)
            XCTAssertEqual(r.configs.map(\.derivedPublicKey), [a.pub, b.pub], root)
        }
    }
    func testDoctypeAndEntityRefused() {
        let evil = Data("<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><wireguard><tunnels><item><name>&e;</name></item></tunnels></wireguard>".utf8)
        XCTAssertThrowsError(try WGParse.load(name: "evil.xml", data: evil)) { XCTAssertTrue($0.localizedDescription.contains("DOCTYPE")) }
        XCTAssertThrowsError(try WGParse.load(name: "e.xml", data: Data("<wireguard><!ENTITY x \"y\"></wireguard>".utf8)))
    }
    func testIPv6FromPfSenseAndPortDigits() throws {
        let k = Self.key()
        let body = tunnel("tun_wg0", k.priv) + "<peers>"
            + peer("tun_wg0", "v6", Self.key().pub, extra: "<endpoint>2001:db8::1</endpoint><port>51820</port><allowedips><row><address>2001:db8::2</address><mask>128</mask></row></allowedips>")
            + peer("tun_wg0", "badport", Self.key().pub, extra: "<endpoint>vpn.example</endpoint><port>+51820</port><allowedips><row><address>198.51.100.3</address><mask>32</mask></row></allowedips>") + "</peers>"
        let r = try WGParse.pfSense(xml(body), name: "x")
        XCTAssertEqual(r.configs[0].peers[0].endpoint, "[2001:db8::1]:51820")
        XCTAssertEqual(r.configs[0].peers[0].allowedIPs, ["2001:db8::2/128"])
        let f = WGCheck.evaluate(r.configs)
        XCTAssertNil(f.first { $0.id == "wg0-peer0-endpoint" })
        XCTAssertEqual(f.first { $0.id == "wg0-peer1-endpoint" }?.severity, .fail)
        XCTAssertNotNil(WGCheck.endpointProblem("h.example:5182a")); XCTAssertNotNil(WGCheck.endpointProblem("h.example: 51820"))
    }
    func testSameNamePeersComparedByIndex() {
        let f = WGCheck.evaluate([peerConf([("dup", Self.key().pub, ["198.51.100.0/24"]), ("dup", Self.key().pub, ["198.51.100.0/24"])])])
        XCTAssertTrue(f.contains { $0.id.hasPrefix("wg0-peer1-overlap") && $0.severity == .fail }, "\(f.map(\.id))")
    }
    func testFullTunnelRules() {
        let single = WGCheck.evaluate([peerConf([("hub", Self.key().pub, ["0.0.0.0/0", "::/0"]), ("lan", Self.key().pub, ["203.0.113.0/24"])])])
        XCTAssertEqual(single.first { $0.id.hasPrefix("wg0-peer1-overlap") }?.severity, .info, "\(single)")
        let multi = WGCheck.evaluate([peerConf([("a", Self.key().pub, ["::/0"]), ("b", Self.key().pub, ["::/0"])])])
        XCTAssertEqual(multi.first { $0.id.hasPrefix("wg0-peer1-overlap") }?.severity, .fail)
    }
    func testHostBitsAndOwnAddress() {
        XCTAssertTrue(CIDR("10.0.0.1/24")!.hostBitsSet); XCTAssertFalse(CIDR("10.0.0.0/24")!.hostBitsSet); XCTAssertFalse(CIDR("10.0.0.1/32")!.hostBitsSet)
        let f = WGCheck.evaluate([peerConf([("a", Self.key().pub, ["198.51.100.5/24"]), ("b", Self.key().pub, ["198.51.100.1/32"])])])
        XCTAssertEqual(f.first { $0.id.hasPrefix("wg0-peer0-hostbits") }?.severity, .warning)
        XCTAssertEqual(f.first { $0.id.hasPrefix("wg0-peer1-ownaddr") }?.severity, .fail)
    }
    func testPrivateKeyPassedAsExpectedIsNeverEchoed() throws {
        let secret = try privateKey(in: "wg-client.conf")
        let r = WGCheck.inspect([fx("wg-client.conf")], expectedPublicKey: secret)
        let f = r.findings.first { $0.id == "wg0-key-expected" }
        XCTAssertEqual(f?.severity, .fail); XCTAssertTrue(f?.title.contains("looks like a private key") == true)
        XCTAssertFalse(r.findings.map { $0.title + $0.detail }.joined().contains(String(secret.prefix(8))))
    }
    func testStatedOutputIsShortened() throws {
        let f = WGCheck.inspect([fx("pfsense-config.xml")]).findings.first { $0.id == "wg0-key-pub" }!
        XCTAssertTrue(f.detail.contains("…")); XCTAssertLessThan(f.detail.count, 160)
    }

    // MARK: 0.2.0 approval follow-ups
    func testKeyCommandCreatesDirAndNeverOverwrites() {
        let g = WGAdvisor.guidance(for: Finding("k", .fail, .wireguard, "t", kind: "key"), platform: .generic)[0]
        let gen = g.commands.first { $0.contains("wg genkey") }!
        XCTAssertTrue(gen.contains("mkdir -p /etc/wireguard")); XCTAssertTrue(gen.contains("set -C")); XCTAssertTrue(gen.contains("wg0.key.new"))
        XCTAssertFalse(gen.contains("tee")); XCTAssertFalse(gen.contains("> /etc/wireguard/wg0.key "))
        XCTAssertTrue(g.steps.joined().contains("refuses to overwrite"))
    }
    func testGenpskSaysClearTerminal() {
        let g = WGAdvisor.guidance(for: Finding("p", .fail, .wireguard, "t", kind: "peer"), platform: .generic)[0]
        XCTAssertTrue(g.commands.first { $0.hasPrefix("wg genpsk") }?.contains("clear the terminal") == true)
        XCTAssertTrue(g.steps.contains { $0.contains("After wg genpsk, clear the terminal") })
    }
    func testExpectPublicFallsBackToStatedKey() {
        let k = Self.key()
        var c = WGConfig(name: "t", source: "pfSense"); c.statedPublicKey = k.pub; c.peers = [WGPeer(name: "p", publicKey: Self.key().pub, allowedIPs: ["198.51.100.2/32"])]
        let pass = WGCheck.evaluate([c], expectedPublicKey: k.pub).first { $0.id == "wg0-key-expected" }
        XCTAssertEqual(pass?.severity, .pass); XCTAssertTrue(pass?.detail.contains("stated public key") == true)
        let fail = WGCheck.evaluate([c], expectedPublicKey: Self.key().pub).first { $0.id == "wg0-key-expected" }
        XCTAssertEqual(fail?.severity, .fail); XCTAssertTrue(fail?.detail.contains("stated") == true)
        let priv = WGCheck.evaluate([c], expectedPublicKey: k.priv)
        XCTAssertTrue(priv.first { $0.id == "wg0-key-expected" }?.title.contains("looks like a private key") == true)
        XCTAssertFalse(priv.map { $0.title + $0.detail }.joined().contains(String(k.priv.prefix(10))))
        var none = WGConfig(name: "n", source: "test"); none.peers = c.peers
        XCTAssertEqual(WGCheck.evaluate([none], expectedPublicKey: k.pub).first { $0.id == "wg0-key-expected" }?.severity, .info)
    }

    // MARK: blank template
    func testBlankTemplateFixtureBytes() throws {
        let raw = try String(contentsOf: fx("wg-blank-template.conf"))
        XCTAssertTrue(raw.contains("\nEndpoint =\n")); XCTAssertTrue(raw.contains("PrivateKey = \n")); XCTAssertTrue(raw.contains("AllowedIPs = \n"))
    }
    func testBlankTemplateParsesEmptyFieldsByName() throws {
        let c = WGParse.wgQuick(try String(contentsOf: fx("wg-blank-template.conf")), name: "blank")
        XCTAssertEqual(c.emptyFields, ["PrivateKey", "Address", "DNS"])
        XCTAssertNil(c.privateKeyStatus); XCTAssertTrue(c.addresses.isEmpty)
        XCTAssertEqual(c.peers.count, 1)
        XCTAssertEqual(c.peers[0].emptyFields, ["PublicKey", "AllowedIPs", "Endpoint"])
        XCTAssertNil(c.peers[0].publicKey); XCTAssertNil(c.peers[0].endpoint); XCTAssertTrue(c.peers[0].allowedIPs.isEmpty)
    }
    func testBlankTemplateReportsEachEmptyField() throws {
        let r = WGCheck.inspect([fx("wg-blank-template.conf")])
        for (id, name) in [("wg0-empty-PrivateKey", "PrivateKey"), ("wg0-empty-Address", "Address"), ("wg0-empty-DNS", "DNS"),
                           ("wg0-peer0-empty-PublicKey", "PublicKey"), ("wg0-peer0-empty-AllowedIPs", "AllowedIPs"), ("wg0-peer0-empty-Endpoint", "Endpoint")] {
            let f = r.findings.first { $0.id == id }
            XCTAssertEqual(f?.severity, name == "DNS" ? .warning : .fail, id); XCTAssertTrue(f?.title.contains("\(name) is empty") == true, id)
        }
        XCTAssertFalse(r.findings.contains { $0.title.contains("PersistentKeepalive") })
        XCTAssertNil(r.findings.first { $0.id == "wg0-peer0-allowed" }, "no duplicate 'no AllowedIPs' warning when the field is blank")
        XCTAssertTrue(r.findings.filter { $0.id.contains("empty-") }.allSatisfy { !$0.kind.isEmpty })
    }

    func testBlankOptionalFieldsAreWarnings() {
        let c = WGParse.wgQuick("[Interface]\nPrivateKey = \(Self.key().priv)\nAddress = 198.51.100.1/24\nMTU = \nDNS =\n[Peer]\nPublicKey = \(Self.key().pub)\nAllowedIPs = 198.51.100.2/32\nPersistentKeepalive = \n", name: "o")
        let f = WGCheck.evaluate([c])
        for id in ["wg0-empty-MTU", "wg0-empty-DNS", "wg0-peer0-empty-PersistentKeepalive"] { XCTAssertEqual(f.first { $0.id == id }?.severity, .warning, id) }
        XCTAssertFalse(f.contains { $0.severity == .fail }, "\(f.filter { $0.severity == .fail }.map(\.title))")
    }
    func testSyntheticWireGuardPackageExport() throws {
        // SYNTHETIC fixture (generated keys, example.test names) modelled on the pfSense WireGuard package; not a real export.
        let r = WGCheck.inspect([fx("SYNTHETIC-pfsense-wireguard-export.xml")])
        XCTAssertEqual(r.configs.map { $0.name.components(separatedBy: " › ").last! }, ["tun_wg0", "tun_wg1"])
        XCTAssertEqual(r.configs.map { $0.peers.count }, [2, 1])
        XCTAssertTrue(r.configs.allSatisfy { $0.privateKeyStatus == .valid && $0.derivedPublicKey == $0.statedPublicKey })
        XCTAssertEqual(r.configs[0].peers[1].allowedIPs, ["198.51.100.3/32", "2001:db8:66::3/128"])
        XCTAssertEqual(r.configs[1].peers[0].endpoint, "fw2.example.test:51821")
        XCTAssertTrue(r.findings.contains { $0.id.contains("disabled-peer") && $0.severity == .info })
        XCTAssertFalse(r.findings.contains { $0.severity == .fail }, "\(r.findings.filter { $0.severity == .fail }.map(\.title))")
        let xml = try String(contentsOf: fx("SYNTHETIC-pfsense-wireguard-export.xml"))
        XCTAssertTrue(xml.contains("SYNTHETIC test fixture"))
        for k in r.configs { _ = k }
        let priv = xml.components(separatedBy: "<privatekey>")[1].prefix(44)
        XCTAssertFalse(r.findings.map { $0.title + $0.detail }.joined().contains(String(priv)))
    }

    func testNotWireGuard() {
        XCTAssertThrowsError(try WGParse.load(name: "x", data: Data("hello".utf8)))
        XCTAssertThrowsError(try WGParse.load(name: "x.xml", data: Data("<pfsense></pfsense>".utf8)))
        XCTAssertThrowsError(try WGParse.load(name: "x.xml", data: Data("<wireguard><tunnels/></wireguard>".utf8)))
    }
}
