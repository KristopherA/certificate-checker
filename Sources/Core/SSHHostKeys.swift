import Foundation
import CryptoKit

// MARK: SSH host keys vs known_hosts (0.9.0). Offline: reads host public keys (ssh_host_*_key.pub files or saved
// ssh-keyscan output) and a known_hosts file. No connection is made. Hashed known_hosts entries (|1|salt|hash) are matched
// with HMAC-SHA1 of the host name, as OpenSSH does. Guidance is copy-only.
public struct SSHKey: Equatable {
    public let type: String
    public let blob: [UInt8]
    public var fingerprint: String { "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "") }
    /// RSA modulus bits from the wire format (string type, mpint e, mpint n); nil for other types.
    public var rsaBits: Int? {
        guard type == "ssh-rsa" else { return nil }
        var i = 0
        func field() -> [UInt8]? {
            guard i + 4 <= blob.count else { return nil }
            let n = blob[i..<i + 4].reduce(0) { $0 << 8 | Int($1) }; i += 4
            guard n >= 0, i + n <= blob.count else { return nil }
            defer { i += n }; return Array(blob[i..<i + n])
        }
        guard field() != nil, field() != nil, let n = field() else { return nil }
        let m = Array(n.drop { $0 == 0 })
        guard let first = m.first else { return 0 }
        return (m.count - 1) * 8 + (8 - first.leadingZeroBitCount)
    }
}

public struct KnownHostsEntry {
    public let patterns: [String]   // plain patterns, or one "|1|salt|hash"
    public let key: SSHKey
    public let marker: String?      // @revoked / @cert-authority
}

public enum SSHHostKeys {
    static let keyTypes: Set<String> = ["ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                                        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"]
    static func key(_ type: String, _ b64: String) -> SSHKey? {
        guard keyTypes.contains(type), let d = Data(base64Encoded: b64) else { return nil }
        let blob = [UInt8](d)
        // The blob starts with its own type string; it must agree with the text type.
        guard blob.count >= 4 else { return nil }
        let n = blob[0..<4].reduce(0) { $0 << 8 | Int($1) }
        guard n > 0, 4 + n <= blob.count, String(decoding: blob[4..<4 + n], as: UTF8.self) == type else { return nil }
        return SSHKey(type: type, blob: blob)
    }
    /// Host keys from .pub files ("type base64 comment") or keyscan lines ("host type base64").
    public static func parseHostKeys(_ text: String) -> [SSHKey] {
        var out: [SSHKey] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let f = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let first = f.first, !first.hasPrefix("#") else { continue }
            if f.count >= 2, let k = key(f[0], f[1]) { out.append(k) }
            else if f.count >= 3, let k = key(f[1], f[2]) { out.append(k) }
        }
        var seen = Set<[UInt8]>(); return out.filter { seen.insert($0.blob).inserted }
    }
    public static func parseKnownHosts(_ text: String) -> [KnownHostsEntry] {
        var out: [KnownHostsEntry] = []
        for line in text.split(whereSeparator: \.isNewline) {
            var f = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let first = f.first, !first.hasPrefix("#") else { continue }
            var marker: String?
            if first.hasPrefix("@") { marker = first; f.removeFirst() }
            guard f.count >= 3, let k = key(f[1], f[2]) else { continue }
            out.append(KnownHostsEntry(patterns: f[0].split(separator: ",").map(String.init), key: k, marker: marker))
        }
        return out
    }
    /// OpenSSH host form: "name", or "[name]:port" when the port is not 22.
    public static func hostToken(_ host: String, port: Int) -> String { port == 22 ? host.lowercased() : "[\(host.lowercased())]:\(port)" }
    static func matches(_ e: KnownHostsEntry, _ token: String) -> Bool {
        var hit = false
        for p in e.patterns {
            if p.hasPrefix("|1|") {
                let parts = p.split(separator: "|", omittingEmptySubsequences: true)
                guard parts.count == 3, let salt = Data(base64Encoded: String(parts[1])), let h = Data(base64Encoded: String(parts[2])) else { continue }
                let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(token.utf8), using: SymmetricKey(data: salt))
                if Data(mac) == h { hit = true }
            } else if p.hasPrefix("!") { if glob(String(p.dropFirst()).lowercased(), token) { return false } }
            else if glob(p.lowercased(), token) { hit = true }
        }
        return hit
    }
    /// Iterative two-pointer wildcard match ('*' and '?'): linear backtracking, no recursion.
    static func glob(_ pattern: String, _ s: String) -> Bool {
        let p = Array(pattern), t = Array(s)
        var i = 0, j = 0, star = -1, mark = 0
        while j < t.count {
            if i < p.count, p[i] == "*" { star = i; mark = j; i += 1 }
            else if i < p.count, p[i] == "?" || p[i] == t[j] { i += 1; j += 1 }
            else if star >= 0 { i = star + 1; mark += 1; j = mark }
            else { return false }
        }
        while i < p.count, p[i] == "*" { i += 1 }
        return i == p.count
    }

    public static func inspect(hostKeys: [SSHKey], knownHosts: [KnownHostsEntry]?, host: String?, port: Int = 22) -> [Finding] {
        func f(_ id: String, _ s: Severity, _ t: Topic, _ title: String, _ d: String = "") -> Finding { Finding(id, s, t, title, d, kind: "ssh") }
        var out: [Finding] = []
        if hostKeys.isEmpty { return [f("ssh-keys", .fail, .general, "No SSH host keys found", "Expected ssh_host_*_key.pub lines or ssh-keyscan output.")] }
        for k in hostKeys {
            let id = "ssh-alg-\(k.type)"
            switch k.type {
            case "ssh-dss": out.append(f(id, .fail, .weakKey, "DSA host key \(k.fingerprint)", "DSA is disabled in OpenSSH 7.0+ and removed in 9.8. Remove it from HostKey in sshd_config."))
            case "ssh-rsa":
                let b = k.rsaBits ?? 0
                if b < 2048 { out.append(f(id, .fail, .weakKey, "RSA host key is \(b) bits", "Generate a new key of at least 3072 bits.")) }
                else if b < 3072 { out.append(f(id, .info, .weakKey, "RSA host key is \(b) bits", "OpenSSH now generates 3072-bit host keys by default.")) }
                else { out.append(f(id, .pass, .weakKey, "RSA host key is \(b) bits")) }
            case "ssh-ed25519": out.append(f(id, .pass, .weakKey, "Ed25519 host key"))
            default: out.append(f(id, .pass, .weakKey, "\(k.type) host key"))
            }
        }
        if !hostKeys.contains(where: { $0.type == "ssh-ed25519" }) { out.append(f("ssh-ed25519", .info, .weakKey, "No Ed25519 host key", "Consider adding one; modern clients prefer it.")) }
        guard let kh = knownHosts, let host, !host.isEmpty else { return out }
        let token = hostToken(host, port: port)
        let entries = kh.filter { matches($0, token) }
        let revoked = entries.filter { $0.marker == "@revoked" }.map(\.key)
        let plain = entries.filter { $0.marker == nil }.map(\.key).filter { !revoked.contains($0) }
        let caKeys = entries.filter { $0.marker == "@cert-authority" }
        for k in hostKeys where revoked.contains(k) { out.append(f("ssh-revoked-\(k.type)", .fail, .trust, "known_hosts marks this \(k.type) key as revoked", k.fingerprint)) }
        if !caKeys.isEmpty { out.append(f("ssh-ca", .info, .trust, "known_hosts trusts \(caKeys.count) SSH certificate authorit\(caKeys.count == 1 ? "y" : "ies") for \(token)", "Host certificates signed by it are accepted; plain host keys (checked here) are compared separately.")) }
        let presented = hostKeys.filter { !revoked.contains($0) }
        if plain.isEmpty { out.append(f("ssh-known", .warning, .trust, "\(token) is not in known_hosts", "Clients will be asked to trust the key on first use. Verify the fingerprint out of band before adding it.")); return out }
        let matched = presented.filter { plain.contains($0) }
        let sameTypeDifferent = presented.filter { k in !plain.contains(k) && plain.contains { $0.type == k.type } }
        for k in sameTypeDifferent {
            out.append(f("ssh-mismatch-\(k.type)", .fail, .keyMismatch, "\(k.type) key does not match known_hosts", "Host now presents \(k.fingerprint). Clients will refuse to connect. Confirm the key was rotated legitimately before running: ssh-keygen -R '\(token)'"))
        }
        if !matched.isEmpty, sameTypeDifferent.isEmpty { out.append(f("ssh-known", .pass, .trust, "known_hosts matches \(matched.count) host key\(matched.count == 1 ? "" : "s")")) }
        let stale = plain.filter { old in !hostKeys.contains(old) && !hostKeys.contains(where: { $0.type == old.type }) }
        if !stale.isEmpty { out.append(f("ssh-stale", .info, .trust, "known_hosts has key types the host no longer offers", stale.map(\.type).joined(separator: ", "))) }
        return out
    }
}
