import Foundation
import CryptoKit

public enum KeyAlgorithm: Equatable, Codable {
    case rsa(bits: Int)
    case ec(curve: String)
    case ed25519
    case other(String)
    public var description: String {
        switch self {
        case .rsa(let b): return "RSA \(b)-bit"
        case .ec(let c): return "ECDSA \(c)"
        case .ed25519: return "Ed25519"
        case .other(let o): return "Other (\(o))"
        }
    }
}

/// Canonical public key material used to compare keys across certificate, CSR and private key.
public struct PublicKeyInfo: Equatable {
    public let algorithm: KeyAlgorithm
    /// RSA: modulus||exponent; EC: uncompressed point; Ed25519: raw key.
    public let material: [UInt8]
    /// Full SubjectPublicKeyInfo DER when known.
    public let spki: [UInt8]?
    public var spkiSHA256: String? { spki.map { Data(SHA256.hash(data: $0)).base64EncodedString() } }

    static func parse(spki node: DERNode) throws -> PublicKeyInfo {
        let parts = try node.children()
        guard parts.count == 2, let alg = try parts[0].children().first?.oid, let bits = parts[1].bitStringBytes else { throw DERError.unexpected("SubjectPublicKeyInfo") }
        let params = try parts[0].children().dropFirst().first
        switch alg {
        case OID.rsaEncryption:
            let k = try DER.parse(bits).children()
            guard k.count >= 2 else { throw DERError.unexpected("RSA key") }
            let n = k[0].unsignedInteger, e = k[1].unsignedInteger
            return PublicKeyInfo(algorithm: .rsa(bits: bitLength(n)), material: n + [0xFF] + e, spki: node.raw)
        case OID.ecPublicKey:
            return PublicKeyInfo(algorithm: .ec(curve: OID.curveName(params?.oid)), material: bits, spki: node.raw)
        case OID.ed25519:
            return PublicKeyInfo(algorithm: .ed25519, material: bits, spki: node.raw)
        default:
            return PublicKeyInfo(algorithm: .other(OID.name(alg)), material: bits, spki: node.raw)
        }
    }
    static func bitLength(_ n: [UInt8]) -> Int {
        guard let first = n.first, first != 0 else { return 0 }
        return (n.count - 1) * 8 + (8 - first.leadingZeroBitCount)
    }
}

public enum OID {
    public static let rsaEncryption = "1.2.840.113549.1.1.1"
    public static let ecPublicKey = "1.2.840.10045.2.1"
    public static let ed25519 = "1.3.101.112"
    public static let san = "2.5.29.17", eku = "2.5.29.37", basicConstraints = "2.5.29.19", keyUsage = "2.5.29.15"
    public static let ski = "2.5.29.14", aki = "2.5.29.35", extensionRequest = "1.2.840.113549.1.9.14"
    public static let serverAuth = "1.3.6.1.5.5.7.3.1", clientAuth = "1.3.6.1.5.5.7.3.2", codeSigning = "1.3.6.1.5.5.7.3.3", emailProtection = "1.3.6.1.5.5.7.3.4", anyEKU = "2.5.29.37.0"
    static let names: [String: String] = [
        "1.2.840.113549.1.1.4": "md5WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA",
        "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.12": "sha384WithRSA", "1.2.840.113549.1.1.13": "sha512WithRSA",
        "1.2.840.113549.1.1.10": "RSASSA-PSS", "1.2.840.10045.4.1": "ecdsaWithSHA1",
        "1.2.840.10045.4.3.2": "ecdsaWithSHA256", "1.2.840.10045.4.3.3": "ecdsaWithSHA384", "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
        "1.3.101.112": "Ed25519", rsaEncryption: "rsaEncryption", ecPublicKey: "ecPublicKey",
        serverAuth: "TLS Web Server Authentication", clientAuth: "TLS Web Client Authentication", codeSigning: "Code Signing",
        emailProtection: "E-mail Protection", anyEKU: "Any Extended Key Usage", "1.3.6.1.5.5.7.3.8": "Time Stamping", "1.3.6.1.5.5.7.3.9": "OCSP Signing",
        "1.3.6.1.5.5.7.3.17": "IPsec IKE", "1.3.6.1.5.5.8.2.2": "IKE Intermediate (Microsoft)", "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon", "1.3.6.1.4.1.311.54.1.2": "Remote Desktop Authentication",
        "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC",
    ]
    public static func name(_ oid: String) -> String { names[oid] ?? oid }
    public static func curveName(_ oid: String?) -> String {
        switch oid { case "1.2.840.10045.3.1.7": return "P-256"; case "1.3.132.0.34": return "P-384"; case "1.3.132.0.35": return "P-521"; default: return oid ?? "unknown curve" }
    }
    public static let weakSignatures: Set<String> = ["1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5", "1.2.840.10045.4.1", "1.2.840.113549.1.1.2"]
}

public struct DistinguishedName: Equatable {
    public let raw: [UInt8]
    public let attributes: [(String, String)]
    public static func == (a: Self, b: Self) -> Bool { a.raw == b.raw }
    public var commonName: String? { attributes.first { $0.0 == "2.5.4.3" }?.1 }
    public var text: String {
        attributes.isEmpty ? "(empty)" : attributes.map { "\(OID.name($0.0))=\($0.1)" }.joined(separator: ", ")
    }
    init(_ node: DERNode) throws {
        raw = node.raw
        var a: [(String, String)] = []
        for set in try node.children() {
            for atv in try set.children() {
                let p = try atv.children()
                if p.count == 2, let o = p[0].oid { a.append((o, p[1].string ?? "<binary>")) }
            }
        }
        attributes = a
    }
}

public struct Certificate: Identifiable {
    public var id: String { sha256 }
    public let der: [UInt8]
    public let version: Int
    public let serialHex: String
    public let signatureAlgorithm: String
    public let issuer: DistinguishedName
    public let subject: DistinguishedName
    public let notBefore: Date
    public let notAfter: Date
    public let publicKey: PublicKeyInfo
    public var dnsNames: [String] = []
    public var ipAddresses: [String] = []
    public var emails: [String] = []
    public var hasSANExtension = false
    public var extendedKeyUsage: [String]? = nil
    public var isCA: Bool? = nil
    /// basicConstraints pathLenConstraint, when present.
    public var pathLen: Int? = nil
    /// True when basicConstraints could not be interpreted (e.g. a negative pathLenConstraint).
    public var basicConstraintsMalformed = false
    public var keyUsageBits: [UInt8]? = nil
    public var subjectKeyID: [UInt8]? = nil
    public var authorityKeyID: [UInt8]? = nil

    public var sha256: String { Data(SHA256.hash(data: der)).map { String(format: "%02X", $0) }.joined(separator: ":") }
    public var sha1: String { Data(Insecure.SHA1.hash(data: der)).map { String(format: "%02X", $0) }.joined(separator: ":") }
    public var isSelfIssued: Bool { issuer == subject }
    public var displayName: String { subject.commonName ?? dnsNames.first ?? subject.text }
    public var signatureIsWeak: Bool { OID.weakSignatures.contains(signatureOID) }
    public let signatureOID: String

    public init(der: [UInt8]) throws {
        self.der = der
        let top = try DER.parse(der)
        guard top.tag == 0x30 else { throw DERError.unexpected("certificate is not a SEQUENCE") }
        let parts = try top.children()
        guard parts.count == 3, parts[0].tag == 0x30 else { throw DERError.unexpected("certificate fields") }
        var tbs = try parts[0].children()[...]
        var version = 1
        if let f = tbs.first, f.tag == 0xA0 { version = (try f.children().first?.intValue ?? 0) + 1; tbs = tbs.dropFirst() }
        let f = Array(tbs)
        guard f.count >= 6, f[0].tag == 0x02 else { throw DERError.unexpected("TBSCertificate") }
        self.version = version
        serialHex = f[0].unsignedInteger.map { String(format: "%02X", $0) }.joined()
        let sigOID = try parts[1].children().first?.oid ?? "unknown"
        signatureOID = sigOID
        signatureAlgorithm = OID.name(sigOID)
        issuer = try DistinguishedName(f[2])
        let validity = try f[3].children()
        guard validity.count == 2, let nb = validity[0].time, let na = validity[1].time else { throw DERError.unexpected("validity") }
        notBefore = nb; notAfter = na
        subject = try DistinguishedName(f[4])
        publicKey = try PublicKeyInfo.parse(spki: f[5])
        for node in f.dropFirst(6) where node.tag == 0xA3 {
            guard let exts = try node.children().first?.children() else { continue }
            for ext in exts { try apply(extension: ext) }
        }
    }

    mutating func apply(extension ext: DERNode) throws {
        let p = try ext.children()
        guard let oid = p.first?.oid, let value = p.last, value.tag == 0x04 else { return }
        let inner = try DER.parse(value.content)
        switch oid {
        case OID.san:
            hasSANExtension = true
            for g in try inner.children() {
                switch g.tag {
                case 0x82: dnsNames.append(String(decoding: g.content, as: UTF8.self))
                case 0x81: emails.append(String(decoding: g.content, as: UTF8.self))
                case 0x87: ipAddresses.append(Certificate.ipString(g.content))
                default: break
                }
            }
        case OID.eku: extendedKeyUsage = try inner.children().compactMap { $0.oid }
        case OID.basicConstraints:
            isCA = try inner.children().first { $0.tag == 0x01 }.map { $0.content.first != 0 } ?? false
            if let node = try inner.children().first(where: { $0.tag == 0x02 }) {
                // pathLenConstraint is INTEGER (0..MAX); a negative or oversized value is malformed, not "unlimited".
                if let v = node.intValue, v >= 0 { pathLen = v } else { basicConstraintsMalformed = true }
            }
        case OID.keyUsage: keyUsageBits = inner.bitStringBytes
        case OID.ski: subjectKeyID = inner.content
        case OID.aki: authorityKeyID = try inner.children().first { $0.tag == 0x80 }?.content
        default: break
        }
    }

    static func ipString(_ b: [UInt8]) -> String {
        if b.count == 4 { return b.map(String.init).joined(separator: ".") }
        if b.count == 16 {
            var a = in6_addr(); withUnsafeMutableBytes(of: &a) { $0.copyBytes(from: b) }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count))
            return String(cString: buf)
        }
        return b.map { String(format: "%02x", $0) }.joined()
    }

    /// RFC 6125-style match: SAN DNS names (single left-most wildcard), SAN IPs; CN only as legacy fallback when no SAN.
    public func matches(hostname: String) -> (matched: Bool, viaCommonNameOnly: Bool) {
        let host = hostname.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if host.contains(":") || host.split(separator: ".").count == 4 && host.allSatisfy({ $0.isNumber || $0 == "." }) {
            let normalized = Certificate.normalizeIP(host)
            return (ipAddresses.contains { Certificate.normalizeIP($0) == normalized }, false)
        }
        if dnsNames.contains(where: { Certificate.wildcardMatch(pattern: $0, host: host) }) { return (true, false) }
        if !hasSANExtension, let cn = subject.commonName, Certificate.wildcardMatch(pattern: cn, host: host) { return (true, true) }
        return (false, false)
    }
    static func normalizeIP(_ s: String) -> String {
        var a6 = in6_addr()
        if inet_pton(AF_INET6, s, &a6) == 1 { return ipString(withUnsafeBytes(of: &a6) { Array($0) }) }
        return s
    }
    public static func wildcardMatch(pattern: String, host: String) -> Bool {
        let p = pattern.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if p == host { return true }
        guard p.hasPrefix("*.") else { return false }
        let suffix = p.dropFirst(2)
        guard suffix.contains("."), let dot = host.firstIndex(of: ".") else { return false }
        let label = host[..<dot]
        return !label.isEmpty && host[host.index(after: dot)...] == suffix
    }
}

public struct CertificateRequest {
    public let subject: DistinguishedName
    public let publicKey: PublicKeyInfo
    public let signatureAlgorithm: String
    public let signatureOID: String
    public var dnsNames: [String] = []
    public var ipAddresses: [String] = []
    public init(der: [UInt8]) throws {
        let p = try DER.parse(der).children()
        guard p.count == 3 else { throw DERError.unexpected("CSR") }
        let info = try p[0].children()
        guard info.count >= 3 else { throw DERError.unexpected("CertificationRequestInfo") }
        subject = try DistinguishedName(info[1])
        publicKey = try PublicKeyInfo.parse(spki: info[2])
        signatureOID = try p[1].children().first?.oid ?? "unknown"
        signatureAlgorithm = OID.name(signatureOID)
        if info.count > 3, info[3].tag == 0xA0 {
            for attr in try info[3].children() {
                let a = try attr.children()
                guard a.first?.oid == OID.extensionRequest, let set = a.last, let exts = try set.children().first?.children() else { continue }
                for ext in exts {
                    let e = try ext.children()
                    guard e.first?.oid == OID.san, let v = e.last else { continue }
                    for g in try DER.parse(v.content).children() {
                        if g.tag == 0x82 { dnsNames.append(String(decoding: g.content, as: UTF8.self)) }
                        if g.tag == 0x87 { ipAddresses.append(Certificate.ipString(g.content)) }
                    }
                }
            }
        }
    }
}

/// A private key parsed only to derive its public half. Callers must not persist instances.
/// The secret bytes are never stored in this type; only derived public material is kept.
public struct PrivateKeyFacts {
    public let publicKey: PublicKeyInfo
    public let format: String

    public static func parse(label: String, der: [UInt8]) throws -> PrivateKeyFacts {
        switch label {
        case "RSA PRIVATE KEY": return try rsa(der, format: "PKCS#1 RSA")
        case "EC PRIVATE KEY": return try ec(der, curveOID: nil, format: "SEC1 EC")
        case "PRIVATE KEY":
            let p = try DER.parse(der).children()
            guard p.count >= 3, let alg = try p[1].children().first?.oid, p[2].tag == 0x04 else { throw DERError.unexpected("PKCS#8 key") }
            switch alg {
            case OID.rsaEncryption: return try rsa(p[2].content, format: "PKCS#8 RSA")
            case OID.ecPublicKey: return try ec(p[2].content, curveOID: try p[1].children().dropFirst().first?.oid, format: "PKCS#8 EC")
            case OID.ed25519:
                let raw = try DER.parse(p[2].content).content
                let k = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
                return PrivateKeyFacts(publicKey: PublicKeyInfo(algorithm: .ed25519, material: [UInt8](k.publicKey.rawRepresentation), spki: nil), format: "PKCS#8 Ed25519")
            default: throw KeyError.unsupported(OID.name(alg))
            }
        case "ENCRYPTED PRIVATE KEY": throw KeyError.encrypted
        default: throw KeyError.unsupported(label)
        }
    }
    static func rsa(_ der: [UInt8], format: String) throws -> PrivateKeyFacts {
        let p = try DER.parse(der).children()
        guard p.count >= 3 else { throw DERError.unexpected("RSA private key") }
        let n = p[1].unsignedInteger, e = p[2].unsignedInteger
        return PrivateKeyFacts(publicKey: PublicKeyInfo(algorithm: .rsa(bits: PublicKeyInfo.bitLength(n)), material: n + [0xFF] + e, spki: nil), format: format)
    }
    static func ec(_ der: [UInt8], curveOID: String?, format: String) throws -> PrivateKeyFacts {
        let p = try DER.parse(der).children()
        guard p.count >= 2, p[1].tag == 0x04 else { throw DERError.unexpected("EC private key") }
        let curve = try curveOID ?? (p.first { $0.tag == 0xA0 }?.children().first?.oid)
        let scalar = p[1].content
        let point: [UInt8]
        switch curve {
        case "1.2.840.10045.3.1.7": point = [UInt8](try P256.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation)
        case "1.3.132.0.34": point = [UInt8](try P384.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation)
        case "1.3.132.0.35": point = [UInt8](try P521.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation)
        default: throw KeyError.unsupported("EC curve \(curve ?? "unknown")")
        }
        return PrivateKeyFacts(publicKey: PublicKeyInfo(algorithm: .ec(curve: OID.curveName(curve)), material: point, spki: nil), format: format)
    }
}

public enum KeyError: Error, LocalizedError, Equatable {
    case encrypted, unsupported(String), password, memoryOnlyUnavailable
    public var errorDescription: String? {
        switch self {
        case .encrypted: return "Encrypted PKCS#8 keys are not decrypted in v0.1. Compare using the certificate's PFX instead, or decrypt to a temporary file on an approved admin workstation."
        case .unsupported(let s): return "Unsupported key type: \(s)."
        case .password: return "The PFX/P12 password is incorrect."
        case .memoryOnlyUnavailable: return "PFX/P12 checks need macOS 15 or later so the file can be opened in memory without importing into a keychain."
        }
    }
}
