import Foundation
import SystemConfiguration

/// Where the address a probe connected to came from.
public enum ResolverSource: String, Equatable {
    case system = "system resolver", override = "connect-IP override", literal = "IP literal"
}

/// Address classes used for the split-DNS / hairpin NAT warning.
public enum IPClass: String, Equatable {
    case loopback, linkLocal = "link-local", rfc1918 = "private (RFC 1918)", ula = "unique local (ULA)", cgnat = "shared (CGNAT, RFC 6598)"
    case documentation, unspecified, multicast, reserved = "reserved / special-use", nat64 = "NAT64 (64:ff9b::/96)", publicAddress = "public"
    /// Addresses that only make sense inside a site (the "office LAN" side of split DNS).
    public var isInternal: Bool { [.rfc1918, .ula, .cgnat].contains(self) }
}

/// Name resolution helpers. Nothing here sends network traffic except `systemLookup`, which is one getaddrinfo call.
public enum Resolution {
    /// True for a numeric IPv4 or IPv6 address (no zone, no brackets, no port).
    public static func isIP(_ s: String) -> Bool {
        guard !s.contains("%") else { return false }   // IPv6 scope IDs (fe80::1%en0) are rejected
        var a4 = in_addr(), a6 = in6_addr()
        return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1
    }

    public static func classify(_ s: String) -> IPClass? {
        guard !s.contains("%") else { return nil }
        var a4 = in_addr(), a6 = in6_addr()
        if inet_pton(AF_INET, s, &a4) == 1 {
            let b = withUnsafeBytes(of: a4.s_addr) { Array($0) }   // network order
            switch (b[0], b[1], b[2]) {
            case (0, _, _): return .unspecified
            case (127, _, _): return .loopback
            case (10, _, _): return .rfc1918
            case (172, 16...31, _): return .rfc1918
            case (192, 168, _): return .rfc1918
            case (100, 64...127, _): return .cgnat
            case (169, 254, _): return .linkLocal
            case (192, 0, 2), (198, 51, 100), (203, 0, 113): return .documentation
            case (224...239, _, _): return .multicast
            case (198, 18...19, _), (192, 0, 0), (240...255, _, _): return .reserved   // benchmarking, IETF protocol assignments, class E and broadcast
            default: return .publicAddress
            }
        }
        if inet_pton(AF_INET6, s, &a6) == 1 {
            let b = withUnsafeBytes(of: a6) { Array($0) }
            if b.allSatisfy({ $0 == 0 }) { return .unspecified }
            if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return .loopback }
            if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xFF && b[11] == 0xFF { return classify("\(b[12]).\(b[13]).\(b[14]).\(b[15])") }
            if b[0] == 0xFE && b[1] & 0xC0 == 0x80 { return .linkLocal }
            if b[0] == 0xFE && b[1] & 0xC0 == 0xC0 { return .reserved }   // fec0::/10, deprecated site-local
            if b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B && b[4..<12].allSatisfy({ $0 == 0 }) { return .nat64 }
            if b[0] & 0xFE == 0xFC { return .ula }
            if b[0] == 0xFF { return .multicast }
            if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8 { return .documentation }
            return .publicAddress
        }
        return nil
    }

    /// Parses a CLI `--resolve HOST:IP` value. The host is everything before the first ':' (hostnames have none),
    /// so IPv6 addresses work unbracketed or in brackets.
    public static func parseOverride(_ s: String) -> (host: String, ip: String)? {
        guard let i = s.firstIndex(of: ":") else { return nil }
        let host = normalizeHost(String(s[..<i]))
        var ip = String(s[s.index(after: i)...])
        if ip.hasPrefix("["), ip.hasSuffix("]") { ip = String(ip.dropFirst().dropLast()) }
        guard Target.validHost(host), !isIP(host), isIP(ip) else { return nil }
        return (host, ip)
    }

    /// Lowercases and strips one trailing dot, so `host.example.test.` and `host.example.test` match.
    public static func normalizeHost(_ s: String) -> String { let l = s.lowercased(); return l.hasSuffix(".") ? String(l.dropLast()) : l }

    public enum OverrideError: Error, Equatable { case invalid(String), conflict(String) }
    /// Collects repeated `--resolve` values. The same host with the same IP twice is fine; with different IPs it is an error.
    public static func mergeOverrides(_ values: [String]) throws -> [String: String] {
        var out: [String: String] = [:]
        for v in values {
            guard let o = parseOverride(v) else { throw OverrideError.invalid(v) }
            if let old = out[o.host], numericForm(old) != numericForm(o.ip) { throw OverrideError.conflict(o.host) }
            out[o.host] = o.ip
        }
        return out
    }
    /// The override that applies to a probed host, matched after `normalizeHost` on both sides.
    public static func override(for host: String, in overrides: [String: String]) -> String? {
        let h = normalizeHost(host)
        return overrides.first { normalizeHost($0.key) == h }?.value
    }
    /// Canonical text for an address (so 2001:db8::1 and 2001:DB8:0::1 compare equal).
    static func numericForm(_ ip: String) -> String {
        var a6 = in6_addr(), a4 = in_addr(), buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if inet_pton(AF_INET6, ip, &a6) == 1, inet_ntop(AF_INET6, &a6, &buf, socklen_t(buf.count)) != nil { return String(cString: buf) }
        if inet_pton(AF_INET, ip, &a4) == 1, inet_ntop(AF_INET, &a4, &buf, socklen_t(buf.count)) != nil { return String(cString: buf) }
        return ip
    }

    /// `Connected to HOST (IP):PORT (SOURCE)`. IPv6 addresses appear bare inside the parentheses.
    /// When the socket's peer address could not be read, the override is shown as *requested*, never as the peer.
    public static func connectedLine(host: String, ip: String?, port: Int, source: ResolverSource, requested: String? = nil) -> String {
        let h = host.contains(":") ? "[\(host)]" : host
        if ip == nil, let requested { return "Connected to \(h):\(port) (\(source.rawValue), requested \(requested); peer address unavailable)" }
        guard let ip, ip != host else { return "Connected to \(h):\(port) (\(source.rawValue))" }
        return "Connected to \(h) (\(ip)):\(port) (\(source.rawValue))"
    }

    /// Numeric peer address of a connected socket.
    public static func peerAddress(fd: Int32) -> String? {
        var ss = sockaddr_storage(); var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let ok = withUnsafeMutablePointer(to: &ss) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &len) } }
        guard ok == 0 else { return nil }
        return numeric(&ss, len)
    }
    static func numeric(_ ss: UnsafeMutablePointer<sockaddr_storage>, _ len: socklen_t) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let rc = ss.withMemoryRebound(to: sockaddr.self, capacity: 1) { getnameinfo($0, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) }
        guard rc == 0 else { return nil }
        var s = String(cString: host)
        if let pct = s.firstIndex(of: "%") { s = String(s[..<pct]) }
        if s.hasPrefix("::ffff:"), isIP(String(s.dropFirst(7))), !String(s.dropFirst(7)).contains(":") { s = String(s.dropFirst(7)) }
        return s
    }

    /// Non-loopback addresses on this Mac's interfaces that are up.
    public static func localAddresses() -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var out: [String] = []
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let flags = Int32(p.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, let sa = p.pointee.ifa_addr else { continue }
            let fam = Int32(sa.pointee.sa_family)
            guard fam == AF_INET || fam == AF_INET6 else { continue }
            var ss = sockaddr_storage()
            withUnsafeMutableBytes(of: &ss) { dst in dst.copyMemory(from: UnsafeRawBufferPointer(start: sa, count: Int(sa.pointee.sa_len))) }
            if let s = numeric(&ss, socklen_t(sa.pointee.sa_len)), classify(s) != .linkLocal { out.append(s) }
        }
        return out
    }

    /// The DNS servers macOS reports for the primary service (State:/Network/Global/DNS), the same list `scutil --dns` shows first.
    public static func systemNameservers() -> [String] {
        guard let store = SCDynamicStoreCreate(nil, "certificate-checker" as CFString, nil, nil),
              let d = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any] else { return [] }
        return (d["ServerAddresses"] as? [String]) ?? []
    }

    /// One getaddrinfo lookup (the system resolver). Used only when a connection failed before a peer address was known.
    public static func systemLookup(_ host: String) -> [String] {
        var hints = addrinfo(); hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(res) }
        var out: [String] = []
        for p in sequence(first: first, next: { $0.pointee.ai_next }) {
            guard let sa = p.pointee.ai_addr else { continue }
            var ss = sockaddr_storage()
            withUnsafeMutableBytes(of: &ss) { dst in dst.copyMemory(from: UnsafeRawBufferPointer(start: sa, count: Int(p.pointee.ai_addrlen))) }
            if let s = numeric(&ss, p.pointee.ai_addrlen), !out.contains(s) { out.append(s) }
        }
        return out
    }

    /// Warns when a hostname resolved (through the system resolver) to a public address while this Mac has an internal
    /// (RFC 1918 / ULA / CGNAT) address: split DNS may be bypassed, and the connection may hairpin through the firewall.
    public static func splitDNSWarning(host: String, addresses: [String], source: ResolverSource, local: [String], nameservers: [String] = []) -> Finding? {
        guard source == .system, !isIP(host) else { return nil }
        let publicIPs = addresses.filter { classify($0) == .publicAddress }
        guard !publicIPs.isEmpty, publicIPs.count == addresses.count else { return nil }
        let internalLocal = local.filter { classify($0)?.isInternal == true }
        guard let mine = internalLocal.first else { return nil }
        var d = "\(host) resolved to \(publicIPs.joined(separator: ", ")) (public) while this Mac has the internal address \(mine). "
        d += "If the site uses split DNS, the internal answer was bypassed and the connection may hairpin through the firewall's NAT, so you may be checking the firewall's certificate instead of the server's. "
        let internalNS = nameservers.filter { classify($0)?.isInternal == true }
        if !internalNS.isEmpty { d += "macOS lists internal DNS servers (\(internalNS.joined(separator: ", "))), so compare `dig @\(internalNS[0]) \(host)` with `dscacheutil -q host -a name \(host)`. " }
        d += "A common cause is iCloud Private Relay / Oblivious DNS (mask.icloud.com): turn off Limit IP address tracking for this network, or block mask.icloud.com and mask-h2.icloud.com in the site DNS. Encrypted-DNS profiles or VPN and proxy DNS can do the same. To check the internal server directly, use --resolve \(host):INTERNAL-IP (or the target's Connect IP)."
        return Finding("split-dns", .warning, .connection, "Public address on an internal network", d)
    }

    /// Extra hint when the certificate name does not match and the split-DNS condition holds.
    public static func firewallHint(_ findings: [Finding], splitDNS: Finding?) -> Finding? {
        guard splitDNS != nil, findings.contains(where: { $0.id == "host" && $0.severity == .fail }) else { return nil }
        return Finding("firewall-hint", .warning, .connection, "Name mismatch may mean the probe reached the firewall",
                       "The certificate does not match and the host resolved to a public address from inside the network. The probe may be reaching the firewall or router (hairpin NAT or its own web UI) instead of the server. Re-check with the server's internal IP as the connect IP before changing the server's certificate.")
    }
}
