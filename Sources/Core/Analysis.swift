import Foundation
import Security

public enum Severity: Int, Codable, Comparable, CaseIterable {
    case pass = 0, info = 1, warning = 2, fail = 3
    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    public var label: String { ["Pass", "Info", "Warning", "Fail"][rawValue] }
}

public enum Topic: String, Codable, CaseIterable {
    case expiry, hostname, chainOrder, chainIncomplete, trust, keyMismatch, weakKey, weakSignature, eku, caLeaf, noSAN, longValidity, startTLS, connection, csr, general, wireguard, ipsec, radius, remote, appliance
}

public struct Finding: Identifiable, Codable, Equatable {
    public var id: String
    public var severity: Severity
    public var topic: Topic
    public var title: String
    public var detail: String
    /// Remediation category used to pick guidance (e.g. WireGuard "key", "peer"); empty when not applicable.
    public var kind: String = ""
    public init(_ id: String, _ severity: Severity, _ topic: Topic, _ title: String, _ detail: String = "", kind: String = "") {
        self.id = id; self.severity = severity; self.topic = topic; self.title = title; self.detail = detail; self.kind = kind
    }
}

public enum Purpose: String, Codable, CaseIterable, Identifiable {
    case tlsServer = "TLS server", tlsClient = "TLS client", any = "Any purpose"
    public var id: String { rawValue }
}

public enum Analysis {
    public static let warnDays = 30

    /// Orders certificates leaf → root by issuer/subject links. Returns nil if no single path covers them.
    public static func orderedChain(_ certs: [Certificate]) -> [Certificate] {
        guard certs.count > 1 else { return certs }
        let issuers = Set(certs.map { $0.issuer.raw })
        // Leaf: a cert whose subject issues nothing else in the set (self-issued roots excluded).
        let leaf = certs.first { c in !certs.contains { o in o.sha256 != c.sha256 && o.issuer == c.subject && !o.isSelfIssued } } ?? certs[0]
        _ = issuers
        var chain = [leaf]; var used: Set<String> = [leaf.sha256]
        while let last = chain.last, !last.isSelfIssued, let next = certs.first(where: { !used.contains($0.sha256) && $0.subject == last.issuer }) {
            chain.append(next); used.insert(next.sha256)
        }
        for c in certs where !used.contains(c.sha256) { chain.append(c) }
        return chain
    }

    public static func evaluate(certificates certs: [Certificate], hostname: String?, purpose: Purpose, keys: [PublicKeyInfo] = [], requests: [CertificateRequest] = [], now: Date = Date()) -> [Finding] {
        var out: [Finding] = []
        guard !certs.isEmpty else {
            if requests.isEmpty && keys.isEmpty { out.append(Finding("none", .fail, .general, "No certificate found", "The input contained no readable PEM, DER, PKCS#7 or PFX certificate.")) }
            for (i, r) in requests.enumerated() { out += evaluate(request: r, index: i, keys: keys) }
            return out
        }
        let chain = orderedChain(certs)
        let leaf = chain[0]

        // Chain order and completeness
        if certs.count > 1 {
            if certs.map(\.sha256) == chain.map(\.sha256) {
                out.append(Finding("order", .pass, .chainOrder, "Chain order is leaf → issuer", chain.map(\.displayName).joined(separator: " → ")))
            } else {
                out.append(Finding("order", .warning, .chainOrder, "Certificates are out of order", "Servers should send the leaf first, then each issuer. Expected: " + chain.map(\.displayName).joined(separator: " → ")))
            }
            for i in 0..<(chain.count - 1) where chain[i].issuer != chain[i+1].subject {
                out.append(Finding("unlinked-\(i)", .warning, .chainIncomplete, "Unrelated certificate in bundle", "\(chain[i+1].displayName) did not issue \(chain[i].displayName)."))
            }
            for i in 0..<(chain.count - 1) where chain[i].issuer == chain[i+1].subject {
                if let aki = chain[i].authorityKeyID, let ski = chain[i+1].subjectKeyID, aki != ski {
                    out.append(Finding("aki-\(i)", .warning, .chainIncomplete, "Authority key ID mismatch", "\(chain[i].displayName) names an issuer key that does not match \(chain[i+1].displayName). The issuing CA may have been re-keyed; use the matching intermediate."))
                }
            }
        }
        if let top = chain.last, !top.isSelfIssued {
            out.append(Finding("top", .info, .chainIncomplete, "Bundle stops at an issued certificate", "The last certificate (\(top.displayName)) was issued by \(top.issuer.text). Servers must send every intermediate; the root may be omitted. Trust evaluation below shows whether this Mac can complete the chain."))
        }

        // Per-certificate checks
        for (i, c) in chain.enumerated() {
            let who = i == 0 ? "Leaf" : "\(c.displayName)"
            let days = Int(c.notAfter.timeIntervalSince(now) / 86_400)
            if now < c.notBefore {
                out.append(Finding("nb-\(i)", .fail, .expiry, "\(who) is not yet valid", "Valid from \(fmt(c.notBefore)). Check the server clock and the certificate issue date."))
            } else if now > c.notAfter {
                out.append(Finding("exp-\(i)", .fail, .expiry, "\(who) expired \(fmt(c.notAfter))", "Renew and deploy a replacement certificate."))
            } else if days <= warnDays {
                out.append(Finding("exp-\(i)", .warning, .expiry, "\(who) expires in \(days) day\(days == 1 ? "" : "s")", "Expires \(fmt(c.notAfter)). Plan renewal now."))
            } else if i == 0 {
                out.append(Finding("exp-\(i)", .pass, .expiry, "Leaf valid for \(days) days", "Expires \(fmt(c.notAfter))."))
            }
            if c.signatureIsWeak && !c.isSelfIssued {
                out.append(Finding("sig-\(i)", .fail, .weakSignature, "\(who) uses a weak signature (\(c.signatureAlgorithm))", "SHA-1 and MD5 signatures are rejected by current clients. Reissue with SHA-256 or stronger."))
            }
            switch c.publicKey.algorithm {
            case .rsa(let bits) where bits < 2048:
                out.append(Finding("key-\(i)", .fail, .weakKey, "\(who) has a weak \(bits)-bit RSA key", "Use RSA 2048-bit or stronger, or ECDSA P-256."))
            case .other(let o):
                out.append(Finding("key-\(i)", .info, .weakKey, "\(who) uses an unrecognised key algorithm", o))
            default: break
            }
        }
        if case .rsa(let bits) = leaf.publicKey.algorithm, bits >= 2048 { out.append(Finding("key-strength", .pass, .weakKey, "Leaf key: RSA \(bits)-bit")) }
        if case .ec(let curve) = leaf.publicKey.algorithm { out.append(Finding("key-strength", .pass, .weakKey, "Leaf key: ECDSA \(curve)")) }
        if !leaf.signatureIsWeak { out.append(Finding("sig", .pass, .weakSignature, "Leaf signature: \(leaf.signatureAlgorithm)")) }

        // Leaf usage
        if leaf.isCA == true && chain.count > 0 && purpose != .any {
            out.append(Finding("ca-leaf", .warning, .caLeaf, "Leaf certificate is a CA certificate", "A server or client certificate should have Basic Constraints CA:FALSE. Check that the correct file was selected."))
        }
        if purpose != .any {
            let needed = purpose == .tlsServer ? OID.serverAuth : OID.clientAuth
            if let eku = leaf.extendedKeyUsage {
                if eku.contains(needed) || eku.contains(OID.anyEKU) {
                    out.append(Finding("eku", .pass, .eku, "Extended key usage allows \(purpose.rawValue.lowercased())"))
                } else {
                    out.append(Finding("eku", .fail, .eku, "Extended key usage does not allow \(purpose.rawValue.lowercased())", "Present: " + eku.map(OID.name).joined(separator: ", ") + ". Reissue from a template that includes \(OID.name(needed))."))
                }
            } else {
                out.append(Finding("eku", .info, .eku, "No extended key usage extension", "Most clients accept this, but CA templates normally include \(OID.name(needed))."))
            }
        }
        if !leaf.hasSANExtension && purpose == .tlsServer {
            out.append(Finding("san", .warning, .noSAN, "Leaf has no Subject Alternative Name", "Browsers, macOS and Java ignore the Common Name for hostname checks. Reissue with the DNS names in the SAN."))
        }
        if let host = hostname?.trimmingCharacters(in: .whitespaces), !host.isEmpty {
            let m = leaf.matches(hostname: host)
            if m.matched && m.viaCommonNameOnly {
                out.append(Finding("host", .warning, .hostname, "\(host) matches only the Common Name", "Add \(host) to the SAN; modern clients will reject this certificate."))
            } else if m.matched {
                out.append(Finding("host", .pass, .hostname, "Certificate covers \(host)"))
            } else {
                let names = (leaf.dnsNames + leaf.ipAddresses)
                out.append(Finding("host", .fail, .hostname, "Certificate does not cover \(host)", names.isEmpty ? "The certificate lists no SAN names." : "Names in certificate: " + names.joined(separator: ", ")))
            }
        }
        let lifetime = Int(leaf.notAfter.timeIntervalSince(leaf.notBefore) / 86_400)
        if purpose == .tlsServer && lifetime > 398 && !leaf.isSelfIssued {
            out.append(Finding("lifetime", .info, .longValidity, "Leaf lifetime is \(lifetime) days", "Publicly trusted TLS certificates are limited to 398 days or less. This is acceptable for a private AD CS or pfSense CA."))
        }

        // Keys
        for (k, key) in keys.enumerated() {
            if let c = chain.first(where: { $0.publicKey.material == key.material }) {
                out.append(Finding("keymatch-\(k)", c.sha256 == leaf.sha256 ? .pass : .warning, .keyMismatch, c.sha256 == leaf.sha256 ? "Private key matches the leaf certificate" : "Private key matches \(c.displayName), not the leaf", "Compared public key material derived in memory."))
            } else {
                out.append(Finding("keymatch-\(k)", .fail, .keyMismatch, "Private key does not match any certificate", "The key's public half differs from every certificate supplied. Find the key generated with this certificate's CSR, or reissue."))
            }
        }
        for (i, r) in requests.enumerated() {
            out += evaluate(request: r, index: i, keys: keys)
            out.append(r.publicKey.material == leaf.publicKey.material
                ? Finding("csr-cert-\(i)", .pass, .csr, "CSR key matches the leaf certificate")
                : Finding("csr-cert-\(i)", .info, .csr, "CSR key differs from the leaf certificate", "Expected after a re-key; a renewal using the same key would match."))
        }
        return out.sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity }
    }

    static func evaluate(request r: CertificateRequest, index i: Int, keys: [PublicKeyInfo]) -> [Finding] {
        var out: [Finding] = [Finding("csr-\(i)", .info, .csr, "CSR for \(r.subject.commonName ?? r.subject.text)", "Key: \(r.publicKey.algorithm.description). SAN: \((r.dnsNames + r.ipAddresses).joined(separator: ", ").ifEmpty("none requested"))")]
        if r.dnsNames.isEmpty && r.ipAddresses.isEmpty { out.append(Finding("csr-san-\(i)", .warning, .noSAN, "CSR requests no SAN names", "Add the service DNS names as SANs before submitting.")) }
        if case .rsa(let b) = r.publicKey.algorithm, b < 2048 { out.append(Finding("csr-key-\(i)", .fail, .weakKey, "CSR key is \(b)-bit RSA", "Generate a 2048-bit or stronger key.")) }
        if OID.weakSignatures.contains(r.signatureOID) { out.append(Finding("csr-sig-\(i)", .warning, .weakSignature, "CSR signed with \(r.signatureAlgorithm)")) }
        for (k, key) in keys.enumerated() where key.material == r.publicKey.material { out.append(Finding("csr-keymatch-\(i)-\(k)", .pass, .keyMismatch, "Private key matches the CSR")) }
        return out
    }

    public static func fmt(_ d: Date) -> String { d.formatted(date: .abbreviated, time: .shortened) }
}

extension String { func ifEmpty(_ s: String) -> String { isEmpty ? s : self } }

public enum Trust {
    public struct Result: Equatable { public let trusted: Bool; public let message: String }
    /// Evaluates with the macOS trust store. Network fetching (AIA/OCSP/CRL) is disabled so offline checks contact nothing.
    public static func evaluate(_ chain: [Certificate], hostname: String?, purpose: Purpose, allowNetwork: Bool = false) -> Result {
        let secCerts = chain.compactMap { SecCertificateCreateWithData(nil, Data($0.der) as CFData) }
        guard !secCerts.isEmpty else { return Result(trusted: false, message: "No certificate could be loaded by macOS.") }
        let host = hostname?.isEmpty == false ? hostname : nil
        let policy: SecPolicy = purpose == .any ? SecPolicyCreateBasicX509() : SecPolicyCreateSSL(purpose == .tlsServer, host as CFString?)
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(secCerts as CFArray, policy, &trust) == errSecSuccess, let trust else { return Result(trusted: false, message: "Trust object could not be created.") }
        SecTrustSetNetworkFetchAllowed(trust, allowNetwork)
        var error: CFError?
        let ok = SecTrustEvaluateWithError(trust, &error)
        return Result(trusted: ok, message: ok ? "Trusted by this Mac's trust settings" : ((error as Error?)?.localizedDescription ?? "Not trusted"))
    }
    public static func finding(_ r: Result, context: String) -> Finding {
        Finding("trust", r.trusted ? .pass : .fail, .trust, r.trusted ? "Trusted by macOS (\(context))" : "Not trusted by macOS (\(context))", r.message)
    }
}
