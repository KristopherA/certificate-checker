import Foundation

// MARK: DKIM (0.9.0). Offline: compares a DKIM DNS TXT record (pasted or saved to a file) with the signing private key.
// No DNS query is made. The private key is read into memory only, never logged, cached or copied. Guidance is copy-only.
public struct DKIMRecord: Equatable {
    public var tags: [String: String] = [:]
    public var publicKey: PublicKeyInfo?
    public var keyType: String { (tags["k"] ?? "rsa").lowercased() }
    public var revoked: Bool { (tags["p"] ?? "").isEmpty }
}

public enum DKIM {
    /// Parses "v=DKIM1; k=rsa; p=MIIB…". Accepts the zone-file form with quotes and line breaks ("…" "…").
    public static func parse(_ text: String) throws -> DKIMRecord {
        var s = text
        if s.contains("\"") { s = s.components(separatedBy: "\"").enumerated().filter { $0.offset % 2 == 1 }.map(\.element).joined() }
        s = s.filter { !$0.isWhitespace }
        guard s.count <= 8_192 else { throw CheckError.message("DKIM record is longer than 8 KB.") }
        var r = DKIMRecord()
        for part in s.split(separator: ";") where !part.isEmpty {
            guard let eq = part.firstIndex(of: "=") else { throw CheckError.message("DKIM tag without '=': \(part.prefix(20))") }
            let k = String(part[..<eq]).lowercased(), v = String(part[part.index(after: eq)...])
            guard r.tags[k] == nil else { throw CheckError.message("DKIM tag \(k)= appears more than once.") }
            r.tags[k] = v
        }
        guard r.tags["p"] != nil else { throw CheckError.message("DKIM record has no p= (public key) tag.") }
        if !r.revoked {
            guard let bytes = Data(base64Encoded: r.tags["p"]!) else { throw CheckError.message("DKIM p= is not valid base64.") }
            switch r.keyType {
            case "rsa": r.publicKey = try PublicKeyInfo.parse(spki: DER.parse([UInt8](bytes)))
            case "ed25519":
                guard bytes.count == 32 else { throw CheckError.message("DKIM ed25519 p= must be 32 bytes, found \(bytes.count).") }
                r.publicKey = PublicKeyInfo(algorithm: .ed25519, material: [UInt8](bytes), spki: nil)
            default: break
            }
        }
        return r
    }

    public static func inspect(_ r: DKIMRecord, privateKey: PublicKeyInfo? = nil) -> [Finding] {
        func f(_ id: String, _ s: Severity, _ t: Topic, _ title: String, _ d: String = "") -> Finding { Finding(id, s, t, title, d, kind: "dkim") }
        var out: [Finding] = []
        if let v = r.tags["v"], v != "DKIM1" { out.append(f("dkim-version", .fail, .general, "v=\(v) is not DKIM1", "Verifiers ignore the record.")) }
        if r.revoked { out.append(f("dkim-revoked", .warning, .general, "Key is revoked (empty p=)", "Mail signed with this selector will fail DKIM.")); return out }
        switch r.keyType {
        case "rsa", "ed25519": break
        default: out.append(f("dkim-type", .fail, .general, "Unknown key type k=\(r.keyType)")); return out
        }
        if case .rsa(let bits)? = r.publicKey?.algorithm {
            if bits < 1024 { out.append(f("dkim-key", .fail, .weakKey, "RSA key is \(bits) bits", "RFC 8301: verifiers must not accept keys under 1024 bits. Use 2048.")) }
            else if bits < 2048 { out.append(f("dkim-key", .warning, .weakKey, "RSA key is \(bits) bits", "1024-bit DKIM keys are considered weak; rotate to 2048.")) }
            else { out.append(f("dkim-key", .pass, .weakKey, "RSA key is \(bits) bits")) }
        } else if r.keyType == "ed25519" {
            out.append(f("dkim-key", .pass, .weakKey, "Ed25519 key", "Many receivers do not verify Ed25519 yet; dual-sign with an RSA selector."))
        }
        if let h = r.tags["h"]?.lowercased().split(separator: ":").map(String.init) {
            if h.contains("sha1") { out.append(f("dkim-hash", h.contains("sha256") ? .warning : .fail, .weakSignature, "h= allows sha1", "RFC 8301: sha1 must not be used. Set h=sha256 or remove h=.")) }
        }
        if let t = r.tags["t"]?.lowercased().split(separator: ":"), t.contains("y") { out.append(f("dkim-testing", .warning, .general, "Testing mode (t=y)", "Receivers may treat failures as if the mail were unsigned.")) }
        if let pk = privateKey {
            if let pub = r.publicKey, pub.algorithm == pk.algorithm, pub.material == pk.material { out.append(f("dkim-match", .pass, .keyMismatch, "Private key matches the DNS record")) }
            else { out.append(f("dkim-match", .fail, .keyMismatch, "Private key does not match the DNS record", "Mail signed with this key will fail DKIM until the record or the signing key is updated.")) }
        } else { out.append(f("dkim-match", .info, .keyMismatch, "No private key supplied", "Supply the signing key to confirm it matches the record.")) }
        return out
    }

    /// Reads a PEM private key (regular file, 2 MB cap) and returns only its public half. The bytes are not kept.
    public static func privateKeyPublicHalf(_ u: URL) throws -> PublicKeyInfo {
        let a = try FileManager.default.attributesOfItem(atPath: u.path)
        guard (a[.type] as? FileAttributeType) == .typeRegular, ((a[.size] as? NSNumber)?.intValue ?? 0) <= FileCheck.maxFileSize else { throw CheckError.message("\(u.lastPathComponent): not a regular file of at most 2 MB.") }
        let text = String(decoding: try Data(contentsOf: u, options: .uncached), as: UTF8.self)
        guard let b = PEM.blocks(text).first(where: { $0.label.hasSuffix("PRIVATE KEY") }) else { throw CheckError.message("\(u.lastPathComponent) holds no PEM private key.") }
        return try PrivateKeyFacts.parse(label: b.label, der: b.der).publicKey
    }
    /// Reads a record file (regular, at most 64 KB).
    public static func recordFile(_ u: URL) throws -> DKIMRecord {
        let a = try FileManager.default.attributesOfItem(atPath: u.path)
        guard (a[.type] as? FileAttributeType) == .typeRegular, ((a[.size] as? NSNumber)?.intValue ?? 0) <= 65_536 else { throw CheckError.message("\(u.lastPathComponent): not a regular file of at most 64 KB.") }
        var t = String(decoding: try Data(contentsOf: u), as: UTF8.self)
        // Zone-file lines: keep only the parenthesised/quoted value.
        if let o = t.firstIndex(of: "("), let c = t.lastIndex(of: ")"), o < c { t = String(t[t.index(after: o)..<c]) }
        else if !t.contains("\""), let v = t.range(of: "v=DKIM1") ?? t.range(of: "p=") { t = String(t[v.lowerBound...]) }
        return try parse(t)
    }
}
