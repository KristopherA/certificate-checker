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

    /// Verifies the signatures along the chain with the top certificate as the only anchor. No network access.
    public static func verify(_ chain: [Certificate], now: Date) -> (ok: Bool, message: String) {
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
