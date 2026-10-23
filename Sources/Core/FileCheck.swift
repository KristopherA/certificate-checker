import Foundation
import Security

/// Result of inspecting local files. Contains only public data; no private key bytes or passwords.
public struct FileReport {
    public var sources: [String] = []
    public var certificates: [Certificate] = []
    public var requests: [CertificateRequest] = []
    public var keyFormats: [String] = []
    public var keys: [PublicKeyInfo] = []
    public var notes: [Finding] = []
    public var findings: [Finding] = []
    public var chain: [Certificate] { Analysis.orderedChain(certificates) }
}

public enum FileCheck {
    public static let maxFileSize = 2 * 1024 * 1024

    /// Inspect files. `password` is used only for PFX/P12 and is not retained.
    public static func inspect(_ urls: [URL], hostname: String?, purpose: Purpose, password: String? = nil, now: Date = Clock.now()) -> FileReport {
        var items: [(String, Data)] = []
        var report = FileReport()
        for url in urls {
            do {
                let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
                guard (attrs[.type] as? FileAttributeType) == .typeRegular else { throw CheckError.message("Not a regular file.") }
                guard ((attrs[.size] as? NSNumber)?.intValue ?? 0) <= maxFileSize else { throw CheckError.message("File is larger than 2 MB.") }
                items.append((url.lastPathComponent, try Data(contentsOf: url, options: .uncached)))
            } catch { report.notes.append(Finding("read-\(url.lastPathComponent)", .fail, .general, "Could not read \(url.lastPathComponent)", error.localizedDescription)) }
        }
        var r = inspect(data: items, hostname: hostname, purpose: purpose, password: password, now: now)
        r.notes = report.notes + r.notes
        r.findings = (report.notes + r.findings)
        return r
    }

    public static func inspect(data items: [(name: String, data: Data)], hostname: String?, purpose: Purpose, password: String? = nil, now: Date = Clock.now()) -> FileReport {
        var r = FileReport()
        for (name, data) in items {
            r.sources.append(name)
            do { try load(name: name, data: data, password: password, into: &r) }
            catch { r.notes.append(Finding("parse-\(name)", .fail, .general, "Could not parse \(name)", error.localizedDescription)) }
        }
        // De-duplicate certificates supplied twice.
        var seen = Set<String>(); r.certificates = r.certificates.filter { seen.insert($0.sha256).inserted }
        var f = r.notes + Analysis.evaluate(certificates: r.certificates, hostname: hostname, purpose: purpose, keys: r.keys, requests: r.requests, now: now)
        if !r.certificates.isEmpty { f.append(Trust.finding(Trust.evaluate(r.chain, hostname: hostname, purpose: purpose, now: now), context: "offline")) }
        r.findings = f.sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity }
        return r
    }

    static func load(name: String, data: Data, password: String?, into r: inout FileReport) throws {
        let bytes = [UInt8](data)
        let ext = (name as NSString).pathExtension.lowercased()
        if ["pfx", "p12"].contains(ext) { try loadPKCS12(data, password: password, into: &r); return }
        if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN ") {
            let blocks = PEM.blocks(text)
            guard !blocks.isEmpty else { throw CheckError.message("PEM markers found but no block could be decoded.") }
            for b in blocks {
                switch b.label {
                case "CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE": r.certificates.append(try Certificate(der: b.der))
                case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST": r.requests.append(try CertificateRequest(der: b.der))
                case "PKCS7": r.certificates += try pkcs7Certificates(b.der)
                case let l where l.hasSuffix("PRIVATE KEY"):
                    let facts = try PrivateKeyFacts.parse(label: l, der: b.der)
                    r.keys.append(facts.publicKey); r.keyFormats.append(facts.format)
                case "PUBLIC KEY": r.keys.append(try PublicKeyInfo.parse(spki: DER.parse(b.der)))
                default: r.notes.append(Finding("pem-\(b.label)", .info, .general, "Skipped PEM block \(b.label)"))
                }
            }
            return
        }
        if let c = try? Certificate(der: bytes) { r.certificates.append(c); return }
        if let csr = try? CertificateRequest(der: bytes) { r.requests.append(csr); return }
        if let certs = try? pkcs7Certificates(bytes), !certs.isEmpty { r.certificates += certs; return }
        if bytes.first == 0x30 && password != nil { try loadPKCS12(data, password: password, into: &r); return }
        throw CheckError.message("Not a recognised PEM, DER certificate, CSR, PKCS#7 or PFX file.")
    }

    /// PKCS#7 / CMS SignedData certificate bag (.p7b/.p7c).
    public static func pkcs7Certificates(_ der: [UInt8]) throws -> [Certificate] {
        let ci = try DER.parse(der).children()
        guard ci.count == 2, ci[0].oid == "1.2.840.113549.1.7.2", let sd = try ci[1].children().first?.children() else { throw CheckError.message("Not PKCS#7 SignedData") }
        guard let bag = sd.first(where: { $0.tag == 0xA0 }) else { return [] }
        return try bag.children().filter { $0.tag == 0x30 }.map { try Certificate(der: $0.raw) }
    }

    /// Opens a PFX strictly in memory (macOS 15+). Nothing is added to any keychain.
    static func loadPKCS12(_ data: Data, password: String?, into r: inout FileReport) throws {
        guard #available(macOS 15.0, *) else { throw KeyError.memoryOnlyUnavailable }
        var items: CFArray?
        let options: [String: Any] = [kSecImportExportPassphrase as String: password ?? "", kSecImportToMemoryOnly as String: true]
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        if status == errSecAuthFailed || status == errSecPkcs12VerifyFailure { throw KeyError.password }
        guard status == errSecSuccess, let list = items as? [[String: Any]] else { throw CheckError.message("PFX could not be opened (OSStatus \(status)).") }
        for item in list {
            if let chain = item[kSecImportItemCertChain as String] as? [SecCertificate] {
                for c in chain { r.certificates.append(try Certificate(der: [UInt8](SecCertificateCopyData(c) as Data))) }
            }
            if let idRef = item[kSecImportItemIdentity as String] {
                let cf = idRef as CFTypeRef
                guard CFGetTypeID(cf) == SecIdentityGetTypeID() else { continue }
                let identity = cf as! SecIdentity // type verified above
                var key: SecKey?
                if SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key, let pub = SecKeyCopyPublicKey(key),
                   let ext = SecKeyCopyExternalRepresentation(pub, nil) as Data? {
                    r.keys.append(try publicInfo(fromSecKeyExternal: [UInt8](ext), attributes: SecKeyCopyAttributes(pub) as? [String: Any] ?? [:]))
                    r.keyFormats.append("PFX identity")
                }
            }
        }
    }

    static func publicInfo(fromSecKeyExternal ext: [UInt8], attributes: [String: Any]) throws -> PublicKeyInfo {
        let type = attributes[kSecAttrKeyType as String] as? String
        if type == (kSecAttrKeyTypeRSA as String) {
            let p = try DER.parse(ext).children()
            guard p.count == 2 else { throw DERError.unexpected("RSA public key") }
            let n = p[0].unsignedInteger
            return PublicKeyInfo(algorithm: .rsa(bits: PublicKeyInfo.bitLength(n)), material: n + [0xFF] + p[1].unsignedInteger, spki: nil)
        }
        let curve: String
        switch ext.count { case 65: curve = "P-256"; case 97: curve = "P-384"; case 133: curve = "P-521"; default: curve = "unknown" }
        return PublicKeyInfo(algorithm: .ec(curve: curve), material: ext, spki: nil)
    }
}

public enum CheckError: Error, LocalizedError, Equatable {
    case message(String)
    public var errorDescription: String? { if case .message(let m) = self { return m }; return nil }
}
