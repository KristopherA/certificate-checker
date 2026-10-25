import Foundation
import Security

/// Protocol-neutral chain helpers shared by the IPsec and RADIUS checks.
public enum ChainCheck {
    /// Apple's 825-day rule applies to certificates with notBefore on or after this date (HT210176).
    public static let appleRuleStart = Date(timeIntervalSince1970: 1_561_939_200) // 2019-07-01T00:00:00Z

    /// Self-issued (subject == issuer) and, as far as key IDs can tell, signed by its own key.
    /// Missing AKI or SKI counts as self-signed; differing IDs mean a rollover (self-issued, new key) certificate.
    public static func isSelfSigned(_ c: Certificate) -> Bool {
        c.isSelfIssued && (c.authorityKeyID == nil || c.subjectKeyID == nil || c.authorityKeyID == c.subjectKeyID)
    }

    /// Leaf → root by subject/issuer, preferring AKI = SKI. Continues through rollover certificates; stops at a
    /// self-signed certificate, when no issuer is found, or after 6 links.
    public static func chain(for leaf: Certificate, pool: [Certificate]) -> [Certificate] {
        var c = [leaf]
        while let last = c.last, !isSelfSigned(last), c.count < 6 {
            let candidates = pool.filter { $0.subject == last.issuer && !c.map(\.sha256).contains($0.sha256) }
            guard let next = candidates.first(where: { last.authorityKeyID == nil || $0.subjectKeyID == last.authorityKeyID }) ?? candidates.first else { break }
            c.append(next)
        }
        return c
    }

    /// True only when `c` is self-issued and its signature verifies with its own public key (SecKeyVerifySignature).
    /// SecTrust never checks an anchor's own signature, so this is what makes a top certificate a real root.
    /// RSASSA-PSS and Ed25519 self-signatures are not checked here and count as unverified.
    public static func selfSignatureVerifies(_ c: Certificate) -> Bool {
        guard c.isSelfIssued, let parts = try? DER.parse(c.der).children(), parts.count == 3,
              let sig = parts[2].bitStringBytes, let alg = secAlgorithm(c.signatureOID),
              let sc = SecCertificateCreateWithData(nil, Data(c.der) as CFData), let key = SecCertificateCopyKey(sc) else { return false }
        return SecKeyVerifySignature(key, alg, Data(parts[0].raw) as CFData, Data(sig) as CFData, nil)
    }

    static func weakLinkMessage(child: Certificate, parent: Certificate) -> String {
        "The signature on \(child.displayName) uses \(child.signatureAlgorithm); MD5 and SHA-1 signatures are not accepted as proof that \(parent.displayName) issued it."
    }

    /// True when `top` is byte-equal to, or has the same SubjectPublicKeyInfo as, one of the user's own certificates
    /// (a CA file or a config's CA list). Only then may a caller pass `trustedTop: true`.
    public static func isUserSupplied(_ top: Certificate, in user: [Certificate]) -> Bool {
        user.contains { $0.der == top.der || $0.publicKey.spki == top.publicKey.spki }
    }

    static func secAlgorithm(_ oid: String) -> SecKeyAlgorithm? {
        switch oid {
        case "1.2.840.113549.1.1.5": return .rsaSignatureMessagePKCS1v15SHA1
        case "1.2.840.113549.1.1.11": return .rsaSignatureMessagePKCS1v15SHA256
        case "1.2.840.113549.1.1.12": return .rsaSignatureMessagePKCS1v15SHA384
        case "1.2.840.113549.1.1.13": return .rsaSignatureMessagePKCS1v15SHA512
        case "1.2.840.10045.4.1": return .ecdsaSignatureMessageX962SHA1
        case "1.2.840.10045.4.3.2": return .ecdsaSignatureMessageX962SHA256
        case "1.2.840.10045.4.3.3": return .ecdsaSignatureMessageX962SHA384
        case "1.2.840.10045.4.3.4": return .ecdsaSignatureMessageX962SHA512
        default: return nil
        }
    }

    /// Verifies the signatures along the chain with the top certificate as the only anchor. No network access.
    /// Unless `trustedTop` is set (the top came from the user, e.g. a supplied CA file, or is pinned), the top must be
    /// a verified self-signed root: otherwise a lone forged leaf, or one with a fake "CA" on top, would anchor itself.
    /// A link signed with MD5 or SHA-1 never counts as proof of issuance (clients reject it, and such signatures can be
    /// forged); web chaincheck.verify refuses the same links. Self-signatures on the top are not links.
    public static func verify(_ chain: [Certificate], now: Date, trustedTop: Bool = false) -> (ok: Bool, message: String) {
        for i in chain.indices.dropLast() where chain[i].signatureIsWeak {
            return (false, weakLinkMessage(child: chain[i], parent: chain[i + 1]))
        }
        if !trustedTop, let top = chain.last, !selfSignatureVerifies(top) {
            return (false, "\(top.displayName) is not a verified self-signed root (\(top.isSelfIssued ? "its signature does not verify with its own key" : "its issuer \(top.issuer.text) was not supplied")), so nothing anchors the chain.")
        }
        let sec = chain.compactMap { SecCertificateCreateWithData(nil, Data($0.der) as CFData) }
        guard sec.count == chain.count, let anchor = sec.last else { return (false, "macOS could not load every certificate.") }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(sec as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, let trust else { return (false, "Trust object could not be created.") }
        SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        SecTrustSetNetworkFetchAllowed(trust, false)
        SecTrustSetVerifyDate(trust, now as CFDate)
        var error: CFError?
        let ok = SecTrustEvaluateWithError(trust, &error)
        return (ok, ok ? "" : ((error as Error?)?.localizedDescription ?? "Signature chain did not verify"))
    }
}
