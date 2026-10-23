import Foundation

// MARK: S/MIME certificate usage and expiry (0.9.0). Offline only: reads certificates already parsed from a file.
// Checks the e-mail protection EKU, key usage for signing and encryption, the address the certificate names,
// expiry, and key and signature strength. Guidance is copy-only.
public enum SMIME {
    static let emailAttr = "1.2.840.113549.1.9.1"
    /// Addresses the certificate names: SAN rfc822Name entries, else the legacy subject emailAddress attribute.
    public static func addresses(_ c: Certificate) -> [String] {
        let san = c.emails.map { $0.lowercased() }
        return san.isEmpty ? c.subject.attributes.filter { $0.0 == emailAttr }.map { $0.1.lowercased() } : san
    }
    static func bit(_ bits: [UInt8]?, _ n: Int) -> Bool {
        guard let b = bits, n / 8 < b.count else { return false }
        return b[n / 8] & (0x80 >> UInt8(n % 8)) != 0
    }
    public static func inspect(_ leaf: Certificate, address: String? = nil, now: Date = Date(), warnDays: Int = 30) -> [Finding] {
        func f(_ id: String, _ s: Severity, _ t: Topic, _ title: String, _ d: String = "") -> Finding { Finding(id, s, t, title, d, kind: "smime") }
        var out: [Finding] = []
        // Usage
        switch leaf.extendedKeyUsage {
        case nil: out.append(f("smime-eku", .warning, .eku, "No Extended Key Usage", "Without the E-mail Protection EKU, some mail clients refuse the certificate for S/MIME."))
        case let e? where e.contains(OID.emailProtection): out.append(f("smime-eku", .pass, .eku, "E-mail Protection EKU present"))
        case let e? where e.contains(OID.anyEKU): out.append(f("smime-eku", .warning, .eku, "Only Any Extended Key Usage", "Clients that require the E-mail Protection EKU will reject it."))
        case let e?: out.append(f("smime-eku", .fail, .eku, "Not valid for e-mail", "EKU lists \(e.map { OID.name($0) }.joined(separator: ", ")) but not E-mail Protection."))
        }
        if leaf.isCA == true { out.append(f("smime-ca", .fail, .caLeaf, "Certificate is a CA", "An S/MIME certificate should be an end-entity certificate.")) }
        if let ku = leaf.keyUsageBits {
            let sign = bit(ku, 0) || bit(ku, 1)
            let enc: Bool
            switch leaf.publicKey.algorithm { case .rsa: enc = bit(ku, 2); case .ec: enc = bit(ku, 4); default: enc = false }
            out.append(f("smime-ku-sign", sign ? .pass : .warning, .eku, sign ? "Key usage allows signing" : "Key usage does not allow signing", sign ? "" : "Digital Signature is not set, so signed mail will not verify."))
            out.append(f("smime-ku-encrypt", enc ? .pass : .info, .eku, enc ? "Key usage allows encryption" : "Key usage does not allow encryption", enc ? "" : "Signing-only certificate: others cannot encrypt mail to this address with it."))
        } else { out.append(f("smime-ku", .info, .eku, "No Key Usage extension", "Any key usage is allowed.")) }
        // Address
        let names = addresses(leaf)
        if names.isEmpty { out.append(f("smime-address", .fail, .hostname, "No e-mail address in the certificate", "Neither the SAN nor the subject names an address, so clients cannot match it to a sender.")) }
        else if let a = address?.trimmingCharacters(in: .whitespaces).lowercased(), !a.isEmpty {
            if names.contains(a) { out.append(f("smime-address", .pass, .hostname, "Certificate names \(a)")) }
            else { out.append(f("smime-address", .fail, .hostname, "Certificate does not name \(a)", "It names \(names.joined(separator: ", ")).")) }
        } else { out.append(f("smime-address", .info, .hostname, "Certificate names \(names.joined(separator: ", "))")) }
        if leaf.emails.isEmpty, !names.isEmpty { out.append(f("smime-san", .warning, .noSAN, "Address only in the subject", "Current S/MIME rules require the address in the SAN as an rfc822Name.")) }
        // Expiry
        let days = Int(leaf.notAfter.timeIntervalSince(now) / 86_400)
        if now < leaf.notBefore { out.append(f("smime-expiry", .fail, .expiry, "Not yet valid", "Valid from \(leaf.notBefore).")) }
        else if days < 0 { out.append(f("smime-expiry", .fail, .expiry, "Expired \(-days) days ago", "New mail cannot be signed or encrypted with it. Keep the key to read old encrypted mail.")) }
        else if days < warnDays { out.append(f("smime-expiry", .warning, .expiry, "Expires in \(days) days", "Renew it and keep the old key for archived mail.")) }
        else { out.append(f("smime-expiry", .pass, .expiry, "Valid for \(days) more days")) }
        // Strength
        switch leaf.publicKey.algorithm {
        case .rsa(let bits) where bits < 2048: out.append(f("smime-key", .fail, .weakKey, "RSA key is \(bits) bits", "Use at least 2048 bits."))
        default: out.append(f("smime-key", .pass, .weakKey, "Key strength OK"))
        }
        if leaf.signatureIsWeak { out.append(f("smime-sig", .fail, .weakSignature, "Weak signature algorithm", leaf.signatureAlgorithm)) }
        return out
    }
}
