import Foundation
import CryptoKit

/// Offline WireGuard configuration checks (wg-quick .conf and pfSense config.xml).
/// Private keys are decoded only to derive the public key; the secret string and bytes are never stored in these
/// types, never placed in findings, and never printed.
public enum WGKey {
    public enum Status: Equatable { case valid, notBase64, wrongLength(Int), nonCanonical }
    public static func decode(_ s: String) -> (Status, [UInt8]?) {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard let d = Data(base64Encoded: t) else { return (.notBase64, nil) }
        guard d.count == 32 else { return (.wrongLength(d.count), nil) }
        guard d.base64EncodedString() == t else { return (.nonCanonical, nil) }
        return (.valid, [UInt8](d))
    }
    public static func describe(_ s: Status) -> String {
        switch s {
        case .valid: return "valid"
        case .notBase64: return "not valid base64"
        case .wrongLength(let n): return "decodes to \(n) bytes, not 32"
        case .nonCanonical: return "is not canonical base64 (44 characters ending in '=')"
        }
    }
    /// Derives the base64 public key. The private key string is not retained.
    public static func publicKey(fromPrivate s: String) -> (Status, String?) {
        let (st, bytes) = decode(s)
        guard st == .valid, let bytes, let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes) else { return (st, nil) }
        return (.valid, k.publicKey.rawRepresentation.base64EncodedString())
    }
}

public struct WGPeer: Equatable {
    public var name: String
    public var publicKey: String?
    public var presharedKeyStatus: WGKey.Status?   // nil = no PSK; the PSK value itself is not kept
    public var allowedIPs: [String] = []
    public var endpoint: String?
    /// Keys present with an empty value (e.g. "AllowedIPs = " in a blank template), in file order.
    public var emptyFields: [String] = []
}

public struct WGConfig: Equatable {
    public var name: String
    public var source: String
    /// nil when the config has no private key (e.g. a pfSense export with keys redacted).
    public var privateKeyStatus: WGKey.Status?
    public var derivedPublicKey: String?
    public var statedPublicKey: String?
    public var addresses: [String] = []
    public var listenPort: String?
    public var peers: [WGPeer] = []
    /// [Interface] keys present with an empty value, in file order.
    public var emptyFields: [String] = []
}

public enum WGParse {
    /// wg-quick INI format. Unknown keys are ignored; key names are case-insensitive.
    public static func wgQuick(_ text: String, name: String) -> WGConfig {
        var c = WGConfig(name: name, source: "wg-quick")
        var section = ""
        var peer: WGPeer?
        func flush() { if let p = peer { c.peers.append(p) }; peer = nil }
        var peerCount = 0
        var pendingName: String?
        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") {
                // Common convention: "# Name = laptop" above a [Peer]
                let body = line.dropFirst().trimmingCharacters(in: .whitespaces)
                if let eq = body.firstIndex(of: "="), body[..<eq].trimmingCharacters(in: .whitespaces).lowercased() == "name" {
                    let v = body[body.index(after: eq)...].trimmingCharacters(in: .whitespaces)
                    if section == "peer", peer != nil, peer?.name.hasPrefix("Peer ") == true { peer?.name = v } else { pendingName = v }
                }
                continue
            }
            if let hash = line.firstIndex(of: "#") { line = String(line[..<hash]).trimmingCharacters(in: .whitespaces) }
            if line.isEmpty { continue }
            if line.hasPrefix("[") {
                flush()
                section = line.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                if section == "peer" { peerCount += 1; peer = WGPeer(name: pendingName ?? "Peer \(peerCount)") ; pendingName = nil }
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            let canonical = ["privatekey": "PrivateKey", "address": "Address", "dns": "DNS", "listenport": "ListenPort", "mtu": "MTU",
                             "publickey": "PublicKey", "presharedkey": "PresharedKey", "allowedips": "AllowedIPs", "endpoint": "Endpoint", "persistentkeepalive": "PersistentKeepalive"]
            if value.isEmpty, let field = canonical[key] {
                // Blank template lines ("Key =" / "Key = ") are recorded by name and not parsed further.
                if section == "interface" { c.emptyFields.append(field) } else if section == "peer" { peer?.emptyFields.append(field) }
                continue
            }
            let list = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            if section == "interface" {
                switch key {
                case "privatekey": let (st, pub) = WGKey.publicKey(fromPrivate: value); c.privateKeyStatus = st; c.derivedPublicKey = pub
                case "address": c.addresses += list
                case "listenport": c.listenPort = value
                default: break
                }
            } else if section == "peer" {
                switch key {
                case "publickey": peer?.publicKey = value
                case "presharedkey": peer?.presharedKeyStatus = WGKey.decode(value).0
                case "allowedips": peer?.allowedIPs += list
                case "endpoint": peer?.endpoint = value
                default: break
                }
            }
        }
        flush()
        return c
    }

    /// pfSense config.xml (WireGuard package): one WGConfig per enabled tunnel, peers grouped by <tun>.
    /// Disabled tunnels/peers and unassigned peers are reported as info, not silently dropped.
    public static func pfSense(_ data: Data, name: String) throws -> (configs: [WGConfig], notes: [Finding]) {
        let lower = String(decoding: data, as: UTF8.self).lowercased()
        guard !lower.contains("<!doctype"), !lower.contains("<!entity") else {
            throw CheckError.message("XML with a DOCTYPE or ENTITY declaration is refused (pfSense exports never contain one).")
        }
        let doc = try XMLDocument(data: data, options: [.nodeLoadExternalEntitiesNever])
        func text(_ n: XMLNode, _ path: String) -> String? {
            guard let v = try? n.nodes(forXPath: path).first?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty else { return nil }
            return v
        }
        func enabled(_ n: XMLNode) -> Bool { text(n, "enabled")?.lowercased() == "yes" }
        func rows(_ n: XMLNode, _ path: String) -> [String] {
            ((try? n.nodes(forXPath: path)) ?? []).compactMap { r in text(r, "address").map { $0 + (text(r, "mask").map { "/\($0)" } ?? "") } }
        }
        var configs: [WGConfig] = [], notes: [Finding] = []
        let tunnels = try doc.nodes(forXPath: "//wireguard/tunnels/item")
        let peers = try doc.nodes(forXPath: "//wireguard/peers/item")
        var active: Set<String> = []
        for t in tunnels {
            let tun = text(t, "name") ?? "tun_wg?"
            guard enabled(t) else { notes.append(Finding("wg-disabled-\(tun)", .info, .wireguard, "\(name) › \(tun) is disabled; skipped", "", kind: "info")); continue }
            active.insert(tun)
            var c = WGConfig(name: "\(name) › \(tun)", source: "pfSense config.xml")
            if let pk = text(t, "privatekey") { let (st, pub) = WGKey.publicKey(fromPrivate: pk); c.privateKeyStatus = st; c.derivedPublicKey = pub }
            c.statedPublicKey = text(t, "publickey")
            c.listenPort = text(t, "listenport")
            c.addresses = rows(t, "addresses/row")
            configs.append(c)
        }
        for (pi, p) in peers.enumerated() {
            let descr = text(p, "descr") ?? "peer #\(pi + 1)"
            let tun = text(p, "tun") ?? "unassigned"
            if tun == "unassigned" || !tunnels.contains(where: { text($0, "name") == tun }) {
                notes.append(Finding("wg-unassigned-\(pi)", .info, .wireguard, "\(name): peer \(descr) is not assigned to a tunnel", "Assign it in VPN › WireGuard › Peers or delete it.", kind: "info")); continue
            }
            guard active.contains(tun) else { continue } // tunnel disabled: already reported
            guard enabled(p) else { notes.append(Finding("wg-disabled-peer-\(pi)", .info, .wireguard, "\(name) › \(tun): peer \(descr) is disabled; skipped", "", kind: "info")); continue }
            var peer = WGPeer(name: descr, publicKey: text(p, "publickey"))
            if let psk = text(p, "presharedkey") { peer.presharedKeyStatus = WGKey.decode(psk).0 }
            peer.allowedIPs = rows(p, "allowedips/row")
            if let host = text(p, "endpoint") {
                let port = text(p, "port") ?? "51820"
                peer.endpoint = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]:\(port)" : "\(host):\(port)"
            }
            if let i = configs.firstIndex(where: { $0.name == "\(name) › \(tun)" }) { configs[i].peers.append(peer) }
        }
        guard !configs.isEmpty || !notes.isEmpty else { throw CheckError.message("No WireGuard tunnels found in this pfSense configuration (expected installedpackages › wireguard › tunnels).") }
        return (configs, notes)
    }

    public static func load(name: String, data: Data) throws -> (configs: [WGConfig], notes: [Finding]) {
        let text = String(decoding: data, as: UTF8.self)
        if text.contains("<pfsense") || text.contains("<wireguard") || text.lowercased().contains("<!doctype") || text.lowercased().contains("<!entity") { return try pfSense(data, name: name) }
        guard text.range(of: "[Interface]", options: .caseInsensitive) != nil || text.range(of: "[Peer]", options: .caseInsensitive) != nil else {
            throw CheckError.message("Not a wg-quick configuration or pfSense config.xml.")
        }
        return ([wgQuick(text, name: name)], [])
    }
}

public struct CIDR: Equatable {
    public let bytes: [UInt8]; public let bits: Int
    public init?(_ s: String) {
        let parts = s.trimmingCharacters(in: .whitespaces).components(separatedBy: "/")
        guard parts.count <= 2, let ip = parts.first, !ip.isEmpty else { return nil }
        var b4 = in_addr(), b6 = in6_addr()
        if inet_pton(AF_INET, ip, &b4) == 1 { bytes = withUnsafeBytes(of: &b4) { Array($0) } }
        else if inet_pton(AF_INET6, ip, &b6) == 1 { bytes = withUnsafeBytes(of: &b6) { Array($0) } }
        else { return nil }
        let maxBits = bytes.count * 8
        if parts.count == 2 {
            let m = parts[1]
            guard !m.isEmpty, m.count <= 3, m.allSatisfy({ $0.isASCII && $0.isNumber }), let n = Int(m), (0...maxBits).contains(n) else { return nil }
            bits = n
        } else { bits = maxBits }
    }
    func bit(_ i: Int) -> UInt8 { (bytes[i / 8] >> (7 - UInt8(i % 8))) & 1 }
    func prefixEqual(_ o: CIDR, _ n: Int) -> Bool { (0..<n).allSatisfy { bit($0) == o.bit($0) } }
    public var isV6: Bool { bytes.count == 16 }
    public var isFullLength: Bool { bits == bytes.count * 8 }
    public var isDefaultRoute: Bool { bits == 0 }
    /// True when address bits beyond the prefix are set (e.g. 198.51.100.1/24).
    public var hostBitsSet: Bool { (bits..<(bytes.count * 8)).contains { bit($0) == 1 } }
    public func overlaps(_ o: CIDR) -> Bool { bytes.count == o.bytes.count && prefixEqual(o, min(bits, o.bits)) }
    public func sameNetwork(_ o: CIDR) -> Bool { bits == o.bits && overlaps(o) }
    public func sameAddress(_ o: CIDR) -> Bool { bytes == o.bytes }
}

public enum WGCheck {
    static func wg(_ id: String, _ s: Severity, _ kind: WGAdvisor.Kind, _ title: String, _ detail: String = "") -> Finding { Finding(id, s, .wireguard, title, detail, kind: kind.rawValue) }
    static func short(_ k: String) -> String { String(k.prefix(8)) + "…" }

    public static func endpointProblem(_ e: String) -> String? {
        var host = "", port = ""
        if e.hasPrefix("[") {
            guard let close = e.firstIndex(of: "]") else { return "IPv6 endpoint is missing ']'" }
            host = String(e[e.index(after: e.startIndex)..<close])
            let rest = e[e.index(after: close)...]
            guard rest.hasPrefix(":") else { return "Endpoint needs a port, e.g. [\(host)]:51820" }
            port = String(rest.dropFirst())
            var b6 = in6_addr(); guard inet_pton(AF_INET6, host, &b6) == 1 else { return "'\(host)' is not an IPv6 address" }
        } else {
            guard let colon = e.lastIndex(of: ":") else { return "Endpoint needs a port, e.g. \(e):51820" }
            host = String(e[..<colon]); port = String(e[e.index(after: colon)...])
            if host.contains(":") { return "IPv6 endpoints must use brackets, e.g. [\(host)]:\(port)" }
            guard Target.validHost(host) else { return "'\(host)' is not a valid host name or address" }
        }
        guard !port.isEmpty, port.count <= 5, port.allSatisfy({ $0.isASCII && $0.isNumber }), let p = Int(port), (1...65535).contains(p) else { return "Port '\(port)' must be digits only, 1–65535" }
        return nil
    }

    /// Settings that may be omitted; a blank line for these is a warning rather than a failure.
    public static let optionalFields: Set<String> = ["DNS", "MTU", "PersistentKeepalive"]

    /// Runs all checks. `expectedPublicKey` optionally pins the local interface key.
    public static func evaluate(_ configs: [WGConfig], expectedPublicKey: String? = nil) -> [Finding] {
        var out: [Finding] = []
        for (ci, c) in configs.enumerated() {
            let p = "wg\(ci)-"
            let label = configs.count > 1 ? "\(c.name): " : ""
            for field in c.emptyFields {
                out.append(wg(p + "empty-\(field)", WGCheck.optionalFields.contains(field) ? .warning : .fail, field == "PrivateKey" ? .key : field == "Address" ? .allowed : .consistency, "\(label)[Interface] \(field) is empty", "The line '\(field) =' has no value. Fill it in, or remove the line if the setting is not needed."))
            }
            switch c.privateKeyStatus {
            case nil: out.append(wg(p + "key-priv", .info, .key, "\(label)No interface private key in this file", "Only peer checks can run. Public-key derivation needs the private key, which stays in memory."))
            case .valid?: out.append(wg(p + "key-priv", .pass, .key, "\(label)Interface private key is a valid Curve25519 key", "Derived public key: \(c.derivedPublicKey ?? "?")"))
            case let st?: out.append(wg(p + "key-priv", .fail, .key, "\(label)Interface private key \(WGKey.describe(st))", "A WireGuard key is 32 bytes encoded as 44 base64 characters."))
            }
            if let stated = c.statedPublicKey {
                let (st, _) = WGKey.decode(stated)
                if st != .valid { out.append(wg(p + "key-pub", .fail, .key, "\(label)Stated public key \(WGKey.describe(st))")) }
                else if let d = c.derivedPublicKey {
                    out.append(d == stated ? wg(p + "key-pub", .pass, .key, "\(label)Stated public key matches the private key")
                                           : wg(p + "key-pub", .fail, .key, "\(label)Stated public key does not match the private key", "Stated \(short(stated)), derived \(short(d)). Peers configured with the stated key will fail the handshake."))
                }
            }
            if let exp = expectedPublicKey?.trimmingCharacters(in: .whitespaces), !exp.isEmpty {
                // Compare against the derived key, or fall back to the stated key (e.g. pfSense <publickey>) when the file has no private key.
                let derivedOK = c.privateKeyStatus == .valid ? c.derivedPublicKey : nil
                let statedOK = c.statedPublicKey.flatMap { WGKey.decode($0).0 == .valid ? $0 : nil }
                if let ref = derivedOK ?? statedOK {
                    let source = derivedOK != nil ? "derived" : "stated"
                    if WGKey.publicKey(fromPrivate: exp).1 == ref {
                        // The supplied value is this interface's PRIVATE key. Never echo it.
                        out.append(wg(p + "key-expected", .fail, .key, "\(label)The expected key looks like a private key", "It derives this interface's public key. Pass the public key instead, and treat the value you entered as exposed if it was shared."))
                    } else if ref == exp {
                        out.append(wg(p + "key-expected", .pass, .key, "\(label)Interface key matches the expected public key", source == "stated" ? "Compared with the stated public key; the file has no private key to derive from." : ""))
                    } else {
                        out.append(wg(p + "key-expected", .fail, .key, "\(label)Interface key does not match the expected public key", "Expected \(short(exp)), \(source) \(short(ref))."))
                    }
                } else {
                    out.append(wg(p + "key-expected", .info, .key, "\(label)Expected public key not checked", "This file has no valid private or stated public key for the interface, so --expect-public cannot be compared."))
                }
            }
            let ifAddrs = c.addresses.compactMap(CIDR.init)
            for a in c.addresses where CIDR(a) == nil { out.append(wg(p + "addr-\(a)", .fail, .allowed, "\(label)Interface Address '\(a)' is not a valid IP/prefix")) }

            if c.peers.isEmpty { out.append(wg(p + "peer-none", .warning, .peer, "\(label)No peers configured")) }
            var seen: [String: String] = [:]
            var nets: [(peer: Int, name: String, text: String, cidr: CIDR)] = []
            for (pi, peer) in c.peers.enumerated() {
                let who = "\(label)\(peer.name)"
                let pp = p + "peer\(pi)-"
                for field in peer.emptyFields {
                    let k: WGAdvisor.Kind = field == "PublicKey" || field == "PresharedKey" ? .peer : field == "AllowedIPs" ? .allowed : field == "Endpoint" ? .endpoint : .consistency
                    out.append(wg(pp + "empty-\(field)", WGCheck.optionalFields.contains(field) ? .warning : .fail, k, "\(who): [Peer] \(field) is empty", "The line '\(field) =' has no value. Fill it in, or remove the line if the setting is not needed."))
                }
                if let pk = peer.publicKey {
                    let (st, _) = WGKey.decode(pk)
                    if st != .valid { out.append(wg(pp + "key", .fail, .peer, "\(who): public key \(WGKey.describe(st))")) }
                    else {
                        if let other = seen[pk] { out.append(wg(pp + "dup", .fail, .peer, "\(who): duplicate peer key", "Same public key as \(other) (\(short(pk))). WireGuard keeps only one; remove the duplicate.")) }
                        seen[pk] = peer.name
                        if pk == c.derivedPublicKey || pk == c.statedPublicKey { out.append(wg(pp + "self", .fail, .peer, "\(who): peer key equals this interface's own key", "A peer must be the remote side's public key. Copy the key from the other end.")) }
                    }
                } else { out.append(wg(pp + "key", .fail, .peer, "\(who): no PublicKey")) }
                if let ps = peer.presharedKeyStatus, ps != .valid { out.append(wg(pp + "psk", .fail, .peer, "\(who): PresharedKey \(WGKey.describe(ps))", "Generate one with wg genpsk; both ends must use the same value.")) }
                if peer.allowedIPs.isEmpty && !peer.emptyFields.contains("AllowedIPs") { out.append(wg(pp + "allowed", .warning, .allowed, "\(who): no AllowedIPs", "No traffic will be routed to or accepted from this peer.")) }
                for a in peer.allowedIPs {
                    guard let cidr = CIDR(a) else { out.append(wg(pp + "allowed-\(a)", .fail, .allowed, "\(who): AllowedIPs entry '\(a)' is not a valid IP/prefix")); continue }
                    if cidr.hostBitsSet { out.append(wg(pp + "hostbits-\(a)", .warning, .allowed, "\(who): AllowedIPs \(a) has host bits set", "WireGuard masks this to the network address; write the network form to avoid confusion.")) }
                    if cidr.isFullLength, ifAddrs.contains(where: { $0.sameAddress(cidr) }) {
                        out.append(wg(pp + "ownaddr-\(a)", .fail, .allowed, "\(who): AllowedIPs \(a) is this interface's own address", "Traffic to the local tunnel address would be sent to the peer. Use the peer's own tunnel address."))
                    }
                    for n in nets where n.peer != pi && n.cidr.overlaps(cidr) {
                        let same = n.cidr.sameNetwork(cidr)
                        let fullTunnel = !same && (n.cidr.isDefaultRoute || cidr.isDefaultRoute)
                        let sev: Severity = same ? .fail : fullTunnel ? .info : .warning
                        let detail = same ? "Cryptokey routing assigns a prefix to one peer only; the later peer silently takes it over."
                                   : fullTunnel ? "One peer carries the full tunnel; more specific prefixes on other peers take precedence, which is usually intended."
                                   : "The more specific prefix wins for routing; confirm this is intended."
                        out.append(wg(pp + "overlap-\(a)-\(n.peer)-\(n.text)", sev, .allowed, "\(who): AllowedIPs \(a) \(same ? "duplicates" : "overlaps") \(n.name)'s \(n.text)", detail))
                    }
                    nets.append((pi, peer.name, a, cidr))
                }
                if let e = peer.endpoint, let problem = endpointProblem(e) { out.append(wg(pp + "endpoint", .fail, .endpoint, "\(who): invalid Endpoint", problem)) }
            }
            if !c.peers.isEmpty && !out.contains(where: { $0.id.hasPrefix(p + "peer") && $0.severity >= .warning }) {
                out.append(wg(p + "peers-ok", .pass, .peer, "\(label)\(c.peers.count) peer\(c.peers.count == 1 ? "" : "s"): keys, AllowedIPs and endpoints are consistent"))
            }
        }
        if configs.count > 1 {
            for (i, a) in configs.enumerated() { for (j, b) in configs.enumerated() where i < j {
                guard let ka = a.derivedPublicKey ?? a.statedPublicKey, let kb = b.derivedPublicKey ?? b.statedPublicKey else { continue }
                let aListsB = a.peers.contains { $0.publicKey == kb }, bListsA = b.peers.contains { $0.publicKey == ka }
                if aListsB && bListsA { out.append(wg("x-\(i)-\(j)", .pass, .consistency, "\(a.name) and \(b.name) list each other's public keys")) }
                else if aListsB || bListsA {
                    let missing = aListsB ? b.name : a.name, key = aListsB ? ka : kb
                    out.append(wg("x-\(i)-\(j)", .fail, .consistency, "Peer key mismatch between \(a.name) and \(b.name)", "\(missing) does not list the other side's public key \(short(key)). One side was probably re-keyed."))
                }
            } }
        }
        return out.sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity }
    }

    public static let maxFileSize = 20 * 1024 * 1024
    /// File text is held in memory for the duration of the check. Swift strings cannot be reliably zeroed, so it is
    /// released (not wiped) when the check returns; only derived public data is kept.
    public static func inspect(_ urls: [URL], expectedPublicKey: String? = nil) -> (configs: [WGConfig], findings: [Finding]) {
        var configs: [WGConfig] = [], notes: [Finding] = []
        for u in urls {
            do {
                let size = (try FileManager.default.attributesOfItem(atPath: u.path)[.size] as? NSNumber)?.intValue ?? 0
                guard size <= maxFileSize else { throw CheckError.message("File is larger than 20 MB.") }
                let r = try WGParse.load(name: u.lastPathComponent, data: Data(contentsOf: u, options: .uncached))
                configs += r.configs; notes += r.notes
            } catch { notes.append(Finding("wg-read-\(u.lastPathComponent)", .fail, .wireguard, "Could not read \(u.lastPathComponent)", error.localizedDescription, kind: "info")) }
        }
        return (configs, (notes + evaluate(configs, expectedPublicKey: expectedPublicKey)).sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity })
    }
}

/// Copy-only WireGuard fix guidance. Commands never print private keys (no `wg showconf`, no `cat` of key files).
public enum WGAdvisor {
    public enum Kind: String { case key, peer, allowed, endpoint, consistency, info }
    public static func kind(of f: Finding) -> Kind { Kind(rawValue: f.kind) ?? .info }
    public static func guidance(for f: Finding, platform: Platform) -> [Guidance] {
        let docs = [KB.wgRunbook, KB.wgCheatSheet, KB.wgHandbook]
        let k = kind(of: f)
        if k == .info { return [] }
        switch platform {
        case .pfSense:
            let steps: [String] = {
                switch k {
                case .key: return ["VPN › WireGuard › Tunnels › edit the tunnel. Use Generate to create a new key pair, or paste the correct private key; pfSense recomputes the public key.", "Update the tunnel's public key on every remote peer.", "Status › WireGuard to confirm handshakes resume."]
                case .peer, .consistency, .info: return ["VPN › WireGuard › Peers: fix or remove the peer entry. The Public Key must be the remote side's key, not this tunnel's.", "Pre-shared Key must be identical on both ends (Generate on one side, copy to the other).", "Status › WireGuard: check Latest Handshake for the peer."]
                case .allowed: return ["VPN › WireGuard › Peers › Allowed IPs: give each peer a unique prefix (typically the peer's tunnel /32 plus any routed LAN).", "Adjust any static routes or firewall rules that reference the old prefixes."]
                case .endpoint: return ["VPN › WireGuard › Peers: Endpoint is a host name or IP only; put the port (digits only) in the Endpoint Port field (default 51820).", "Leave Endpoint empty for roaming clients that connect to this firewall."]
                }
            }()
            return [Guidance(title: "pfSense WireGuard", steps: steps + ["Run the commands below on the firewall in Diagnostics › Command Prompt, or an SSH shell (menu option 8)."], commands: ["wg show all latest-handshakes", "wg show all allowed-ips"], docs: docs)]
        case .macOS:
            let steps: [String] = {
                switch k {
                case .key: return ["In the WireGuard app, select the tunnel: the Interface pane shows its Public key. Choose Edit to change the PrivateKey (the app recomputes the public key), or create a new tunnel with Add Empty Tunnel to get a fresh key pair.", "Give the new public key to the other side."]
                default: return ["In the WireGuard app, select the tunnel and choose Edit. Correct the [Peer] PublicKey, PresharedKey, AllowedIPs or Endpoint named in the finding.", "Activate the tunnel; the Peer pane shows Latest handshake and data transferred."]
                }
            }()
            return [Guidance(title: "macOS WireGuard app", steps: steps + ["The app stores tunnel configs in the Keychain; don't export edited configs to synced folders."], commands: [], docs: docs)]
        default:
            let cmds: [String] = {
                switch k {
                case .key: return ["sudo sh -c 'umask 077; mkdir -p /etc/wireguard && set -C && wg genkey > /etc/wireguard/wg0.key.new && wg pubkey < /etc/wireguard/wg0.key.new'", "sudo wg show wg0 public-key"]
                case .peer, .consistency, .info: return ["sudo wg show wg0 peers", "wg genpsk  # paste into PresharedKey on both ends, then clear the terminal and scrollback (Cmd-K, or: clear && printf '\\033[3J')", "sudo wg show wg0 latest-handshakes"]
                case .allowed: return ["sudo wg show wg0 allowed-ips", "ip route show table all | grep wg0"]
                case .endpoint: return ["sudo wg show wg0 endpoints"]
                }
            }()
            return [Guidance(title: "Linux wg-quick", steps: ["Edit /etc/wireguard/wg0.conf (mode 600, owner root) and correct the field in the finding.", "Apply without dropping other peers with the syncconf command below, or restart the interface with wg-quick.", "Never paste private keys into tickets or chat.", "Key generation writes wg0.key.new and refuses to overwrite (set -C): put its contents in PrivateKey in wg0.conf, then shred/remove the .new file. If wg0.key.new already exists, deal with it first.", "After wg genpsk, clear the terminal and its scrollback so the key isn't left on screen."], commands: cmds + ["sudo bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'", "sudo wg-quick down wg0 && sudo wg-quick up wg0"], docs: docs)]
        }
    }
}
