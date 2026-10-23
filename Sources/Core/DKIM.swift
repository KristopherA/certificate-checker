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
    /// Strict: parses exactly one record, "v=DKIM1; k=rsa; p=MIIB…" or its quoted form ("…" "…"). Every tag must be
    /// well formed and appear once; anything else throws. Use record(in:selector:) for zone-file excerpts.
    public static func parse(_ text: String) throws -> DKIMRecord {
        let r = try zoneRecords(text)
        guard r.count == 1 else { throw CheckError.message("Expected one record, found \(r.count). Use record(in:selector:) for zone excerpts.") }
        return try parseValue(r[0].value)
    }
    /// Parses an unquoted record value into tags.
    static func parseValue(_ text: String) throws -> DKIMRecord {
        var s = text
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
    /// Reads a record file (regular, at most 64 KB). Accepts a bare record, or zone-file lines with `;` comments,
    /// parentheses, quoted strings and \X / \DDD escapes. A file with several DKIM records needs `selector`.
    public static func recordFile(_ u: URL, selector: String? = nil) throws -> DKIMRecord {
        let a = try FileManager.default.attributesOfItem(atPath: u.path)
        guard (a[.type] as? FileAttributeType) == .typeRegular, ((a[.size] as? NSNumber)?.intValue ?? 0) <= 65_536 else { throw CheckError.message("\(u.lastPathComponent): not a regular file of at most 64 KB.") }
        return try record(in: String(decoding: try Data(contentsOf: u), as: UTF8.self), selector: selector)
    }

    public struct ZoneRecord: Equatable { public var owner: String?; public var value: String
        /// "sel" from "sel._domainkey.example.com." (nil when the owner is missing or not a DKIM name).
        public var selector: String? { owner.flatMap { o in o.lowercased().range(of: "._domainkey").map { String(o[..<$0.lowerBound]).lowercased() } } }
    }

    public static func record(in text: String, selector: String? = nil) throws -> DKIMRecord {
        var t = text
        // A bare record in a file may follow a label or notes; start at the record itself.
        if !t.contains("\""), let v = t.range(of: "v=DKIM1") ?? t.range(of: "p=") { t = String(t[v.lowerBound...]) }
        let all = try zoneRecords(t)
        var dkim = all.filter { isDKIM($0.value) }
        if let sel = selector?.lowercased() {
            dkim = dkim.filter { $0.selector == sel }
            guard !dkim.isEmpty else { throw CheckError.message("No DKIM record for selector \(sel). Found: \(selectorList(all)).") }
        }
        guard let first = dkim.first else { throw CheckError.message("No DKIM record (v=DKIM1 or p=) found.") }
        guard dkim.count == 1 else { throw CheckError.message("Found \(dkim.count) DKIM records (selectors: \(selectorList(dkim))). Pass --selector NAME.") }
        return try parseValue(first.value)
    }
    static func selectorList(_ r: [ZoneRecord]) -> String { let s = r.compactMap(\.selector); return s.isEmpty ? "none named" : s.joined(separator: ", ") }

    /// Splits text into TXT records. Without any quote the whole text is one bare record.
    /// Throws on an unterminated quote or a \\DDD escape above 255. Quoted strings that belong to a
    /// following non-TXT record (CAA, SPF-type RRs, …) are not added to the TXT record before it.
    /// A blank line or a `$TTL`/`$ORIGIN` directive ends the current record; a quoted-only line after that starts a new
    /// record with no owner. Inside `( … )`, unquoted words are character-strings too (bare continuation lines).
    static func zoneRecords(_ text: String) throws -> [ZoneRecord] {
        guard text.contains("\"") else { return [ZoneRecord(owner: nil, value: text)] }
        var out: [ZoneRecord] = [], depth = 0, current: ZoneRecord?, ignoring = false
        func close() { if let c = current { out.append(c) }; current = nil }
        for (ln, raw) in text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init).enumerated() {
            // Ordered pieces: (text, quoted). Comments (';' outside quotes) end the line.
            var pieces: [(String, Bool)] = [], inQ = false, buf = "", word = "", i = 0
            let chars = Array(raw), depthAtStart = depth
            func flushWord() { if !word.isEmpty { pieces.append((word, false)); word = "" } }
            while i < chars.count {
                let c = chars[i]
                if inQ {
                    if c == "\\", i + 1 < chars.count {
                        if i + 3 < chars.count, chars[(i + 1)...(i + 3)].allSatisfy({ $0.isASCII && $0.isNumber }) {
                            let n = Int(String(chars[(i + 1)...(i + 3)]))!
                            guard n < 256 else { throw CheckError.message("Line \(ln + 1): escape \\\(n) is above 255.") }
                            buf.append(Character(UnicodeScalar(UInt8(n)))); i += 4; continue
                        }
                        buf.append(chars[i + 1]); i += 2; continue
                    }
                    if c == "\"" { inQ = false; pieces.append((buf, true)); buf = "" } else { buf.append(c) }
                } else {
                    if c == ";" { break }                       // zone-file comment
                    if c == "\"" { flushWord(); inQ = true }
                    else if c == "(" { flushWord(); depth += 1 }
                    else if c == ")" { flushWord(); depth = max(0, depth - 1) }
                    else if c.isWhitespace { flushWord() } else { word.append(c) }
                }
                i += 1
            }
            guard !inQ else { throw CheckError.message("Line \(ln + 1): unterminated quoted string.") }
            flushWord()
            let words = pieces.filter { !$0.1 }.map(\.0)
            if depthAtStart == 0 && pieces.isEmpty {
                // A blank (or comment-only) line ends the record outside parentheses.
                if raw.trimmingCharacters(in: .whitespaces).isEmpty { close(); ignoring = false }   // comment-only lines change nothing
                continue
            }
            if depthAtStart == 0, let w = words.first, w.hasPrefix("$") { close(); ignoring = false; continue }   // $TTL, $ORIGIN
            if let ti = pieces.firstIndex(where: { !$0.1 && $0.0.uppercased() == "TXT" }) {
                close()
                let hasOwner = raw.first.map { !$0.isWhitespace } == true && words.first.map { !["TXT", "IN"].contains($0.uppercased()) } == true
                current = ZoneRecord(owner: hasOwner ? words.first : nil, value: pieces[(ti + 1)...].map(\.0).joined()); ignoring = false
            } else if depthAtStart > 0 {
                if !ignoring { current?.value += pieces.map(\.0).joined() }
            } else if !words.isEmpty {
                // Another resource record (or stray text) starts here: close the TXT record and skip its strings.
                close(); ignoring = true
            } else if !ignoring {
                if current == nil { current = ZoneRecord(owner: nil, value: "") }
                current?.value += pieces.map(\.0).joined()
            }
        }
        close()
        return out
    }
    /// A DKIM key record starts with v=DKIM1, or has no v= tag and has p= (RFC 6376 §3.6.1). DMARC, SPF etc. do not count.
    static func isDKIM(_ value: String) -> Bool {
        let v = value.filter { !$0.isWhitespace }
        let keys = v.split(separator: ";").compactMap { $0.split(separator: "=", maxSplits: 1).first.map { $0.lowercased() } }
        return v.hasPrefix("v=DKIM1") || (!keys.contains("v") && keys.contains("p"))
    }
}
