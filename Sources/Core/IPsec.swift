import Foundation
import Security

/// IKEv2 IPsec certificate checks for pfSense mobile/site-to-site VPNs. Offline only: no IKE packets are sent.
/// Private keys (PEM files or config.xml <prv>) are parsed in memory only to derive the public half for matching;
/// they are never stored, logged or output. Raw file text is not zeroed; it is released when the check ends.
public struct IPsecEntry {
    public let label: String
    public let cert: Certificate
    public let refid: String?
    /// Public half of the private key stored with this entry (config.xml <prv>), if any.
    let ownKey: PublicKeyInfo?
}

public struct IPsecReport {
    public var sources: [String] = []
    public var servers: [IPsecEntry] = []
    public var cas: [IPsecEntry] = []
    public var findings: [Finding] = []
}

public enum IPsecParse {
    /// An enabled IPsec Phase 1 that authenticates with a certificate.
    struct P1 { let index: Int; let descr: String; let certref: String?; let caref: String?; let mobile: Bool }
    struct Loaded { var entries: [IPsecEntry] = []; var keys: [PublicKeyInfo] = []; var notes: [Finding] = []; var phase1: [P1] = [] }

    static func load(name: String, data: Data, into l: inout Loaded) throws {
        let head = String(decoding: data.prefix(4096), as: UTF8.self).lowercased()
        if head.contains("<?xml") || head.contains("<pfsense") || head.contains("<!doctype") || head.contains("<cert>") || head.contains("<ca>") {
            try pfSense(data, name: name, into: &l); return
        }
        var r = FileReport()
        try FileCheck.load(name: name, data: data, password: nil, into: &r)
        l.entries += r.certificates.map { IPsecEntry(label: $0.displayName, cert: $0, refid: nil, ownKey: nil) }
        l.keys += r.keys
        l.notes += r.notes
    }

    /// pfSense config.xml: <cert>/<ca> entries (base64 PEM in <crt>, key in <prv>) and IPsec phase 1 certref/caref.
    static func pfSense(_ data: Data, name: String, into l: inout Loaded) throws {
        let lower = String(decoding: data, as: UTF8.self).lowercased()
        guard !lower.contains("<!doctype"), !lower.contains("<!entity") else {
            throw CheckError.message("XML with a DOCTYPE or ENTITY declaration is refused (pfSense exports never contain one).")
        }
        let doc = try XMLDocument(data: data, options: [.nodeLoadExternalEntitiesNever])
        func text(_ n: XMLNode, _ path: String) -> String? {
            guard let v = try? n.nodes(forXPath: path).first?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty else { return nil }
            return v
        }
        func pem(_ b64: String) -> String? { Data(base64Encoded: b64, options: .ignoreUnknownCharacters).map { String(decoding: $0, as: UTF8.self) } }
        var found = 0
        for tag in ["ca", "cert"] {
            for (i, n) in ((try? doc.nodes(forXPath: "//\(tag)[not(ancestor::ipsec)]")) ?? []).enumerated() {
                let descr = text(n, "descr") ?? "\(tag) #\(i + 1)"
                guard let crt = text(n, "crt") else {
                    if text(n, "csr") != nil { l.notes.append(Finding("ipsec-csr-\(tag)\(i)", .info, .ipsec, "\(descr): pending CSR, no certificate yet", kind: "info")) }
                    continue
                }
                guard let p = pem(crt), let block = PEM.blocks(p).first(where: { $0.label.hasSuffix("CERTIFICATE") }) else {
                    l.notes.append(Finding("ipsec-bad-\(tag)\(i)", .fail, .ipsec, "\(descr): <crt> is not a base64 PEM certificate", kind: "chain")); continue
                }
                do {
                    let cert = try Certificate(der: block.der)
                    var own: PublicKeyInfo?
                    if let prv = text(n, "prv") {
                        if let kp = pem(prv), let kb = PEM.blocks(kp).first(where: { $0.label.hasSuffix("PRIVATE KEY") }) {
                            do { own = try PrivateKeyFacts.parse(label: kb.label, der: kb.der).publicKey }
                            catch { l.notes.append(Finding("ipsec-prv-\(tag)\(i)", .warning, .ipsec, "\(descr): stored private key could not be read", error.localizedDescription, kind: "keymatch")) }
                        } else { l.notes.append(Finding("ipsec-prv-\(tag)\(i)", .warning, .ipsec, "\(descr): <prv> is not a base64 PEM private key", kind: "keymatch")) }
                    }
                    l.entries.append(IPsecEntry(label: descr, cert: cert, refid: text(n, "refid"), ownKey: own)); found += 1
                } catch { l.notes.append(Finding("ipsec-bad-\(tag)\(i)", .fail, .ipsec, "\(descr): certificate could not be parsed", error.localizedDescription, kind: "chain")) }
            }
        }
        for (i, p1) in ((try? doc.nodes(forXPath: "//ipsec/phase1")) ?? []).enumerated() {
            let ike = text(p1, "iketype")?.lowercased()
            let descr = (text(p1, "descr") ?? "Phase 1 #\(i + 1)") + (ike == "ikev1" ? " (IKEv1)" : "")
            // pfSense writes <disabled/> (empty element) for a disabled Phase 1, so test presence, not text.
            guard ((try? p1.nodes(forXPath: "disabled")) ?? []).isEmpty else {
                l.notes.append(Finding("ipsec-p1-disabled-\(i)", .info, .ipsec, "\(descr) is disabled; skipped", kind: "info")); continue
            }
            guard let certref = text(p1, "certref") else { continue }   // PSK or EAP-only Phase 1: no server certificate
            let mobileNodes = (try? p1.nodes(forXPath: "mobile")) ?? []
            let mobile = !mobileNodes.isEmpty && !["false", "no", "0"].contains(mobileNodes.first?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? "")
            l.phase1.append(P1(index: i, descr: descr, certref: certref, caref: text(p1, "caref"), mobile: mobile))
        }
        guard found > 0 || !l.notes.isEmpty else { throw CheckError.message("No <cert> or <ca> entries with a certificate were found in \(name).") }
    }
}

public enum IPsecCheck {
    public static let appleMaxDays = 825
    /// Same cap as WireGuard (config.xml backups with RRD data can be large).
    public static let maxFileSize = 20 * 1024 * 1024
    /// Apple's 825-day rule applies to certificates with notBefore on or after this date (HT210176).
    public static let appleRuleStart = ChainCheck.appleRuleStart
    static let sha2Signatures: Set<String> = ["1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13", "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4"]
    static let pss = "1.2.840.113549.1.1.10"
    public static let ikeIntermediate = "1.3.6.1.5.5.8.2.2", ipsecIKE = "1.3.6.1.5.5.7.3.17"

    static func f(_ id: String, _ s: Severity, _ kind: String, _ title: String, _ detail: String = "") -> Finding { Finding(id, s, .ipsec, title, detail, kind: kind) }

    public static func inspect(_ urls: [URL], expectedIdentifier: String? = nil, now: Date = Clock.now()) -> IPsecReport {
        var items: [(String, Data)] = []; var pre: [Finding] = []
        for url in urls {
            do {
                let a = try FileManager.default.attributesOfItem(atPath: url.path)
                guard (a[.type] as? FileAttributeType) == .typeRegular else { throw CheckError.message("Not a regular file.") }
                guard ((a[.size] as? NSNumber)?.intValue ?? 0) <= maxFileSize else { throw CheckError.message("File is larger than 20 MB.") }
                items.append((url.lastPathComponent, try Data(contentsOf: url, options: .uncached)))
            } catch { pre.append(f("read-\(url.lastPathComponent)", .fail, "info", "Could not read \(url.lastPathComponent)", error.localizedDescription)) }
        }
        var r = inspect(data: items, expectedIdentifier: expectedIdentifier, now: now)
        r.findings = sort(pre + r.findings)
        return r
    }

    public static func inspect(data items: [(name: String, data: Data)], expectedIdentifier: String? = nil, now: Date = Clock.now()) -> IPsecReport {
        var l = IPsecParse.Loaded(); var r = IPsecReport()
        for (name, data) in items {
            r.sources.append(name)
            do { try IPsecParse.load(name: name, data: data, into: &l) }
            catch { l.notes.append(f("parse-\(name)", .fail, "info", "Could not parse \(name)", error.localizedDescription)) }
        }
        var seen = Set<String>(); l.entries = l.entries.filter { seen.insert($0.cert.sha256).inserted }
        r.cas = l.entries.filter { e in e.cert.isCA == true || (e.cert.isSelfIssued && e.cert.isCA == nil && l.entries.contains { o in o.cert.sha256 != e.cert.sha256 && o.cert.issuer == e.cert.subject }) }
        var servers = l.entries.filter { e in !r.cas.contains { $0.cert.sha256 == e.cert.sha256 } }
        var out = l.notes
        // Restrict to the certificates IPsec phase 1 actually uses, when config.xml names them.
        let refs = Set(l.phase1.compactMap(\.certref))
        if !refs.isEmpty {
            let unused = servers.filter { $0.refid != nil && !refs.contains($0.refid!) }
            if !unused.isEmpty { out.append(f("ipsec-unused", .info, "info", "\(unused.count) certificate\(unused.count == 1 ? "" : "s") not used by IPsec skipped", unused.map(\.label).joined(separator: ", "))) }
            servers = servers.filter { $0.refid == nil || refs.contains($0.refid!) }
            for p in l.phase1 where p.certref != nil && !l.entries.contains(where: { $0.refid == p.certref }) {
                out.append(f("ipsec-p1-missing-\(p.certref!)", .fail, "chain", "\(p.descr): My Certificate refers to a certificate that is not in the file", "certref \(p.certref!)"))
            }
        }
        else if servers.contains(where: { $0.refid != nil }) {
            // config.xml with no certificate-based Phase 1: check only serverAuth certificates as candidates.
            let other = servers.filter { $0.refid != nil && $0.cert.extendedKeyUsage?.contains(OID.serverAuth) != true }
            servers = servers.filter { $0.refid == nil || $0.cert.extendedKeyUsage?.contains(OID.serverAuth) == true }
            out.append(f("ipsec-nop1", .info, "info", "No enabled Phase 1 uses a certificate", "Checked \(servers.count) certificate\(servers.count == 1 ? "" : "s") with the serverAuth EKU as IKEv2 server candidates."))
            if !other.isEmpty { out.append(f("ipsec-notserver", .info, "info", "\(other.count) non-server certificate\(other.count == 1 ? "" : "s") skipped", other.map(\.label).joined(separator: ", "))) }
        }
        r.servers = servers
        if !servers.isEmpty { out.append(f("ipsec-revocation", .info, "chain", "Revocation is not checked", "This check is offline, so CRLs and OCSP are not fetched. Confirm in System › Cert. Manager › Certificate Revocation that the certificate is not revoked.")) }
        if servers.isEmpty { out.append(f("ipsec-noserver", r.cas.isEmpty ? .fail : .info, "info", r.cas.isEmpty ? "No certificate found" : "No server certificate supplied; checked the CA only")) }
        let pool = r.cas + servers
        for (i, s) in servers.enumerated() {
            let p1 = l.phase1.filter { $0.certref != nil && $0.certref == s.refid }
            out += evaluate(server: s, index: i, label: servers.count > 1 ? "\(s.label): " : "", pool: pool, phase1: p1, cas: r.cas, expected: expectedIdentifier, now: now)
        }
        for (ci, ca) in r.cas.enumerated() { out += evaluate(ca: ca, index: ci, now: now) }
        // Private keys supplied as separate files.
        for (k, key) in l.keys.enumerated() {
            if let s = servers.first(where: { $0.cert.publicKey.material == key.material }) {
                out.append(f("ipsec-key-\(k)", .pass, "keymatch", "Private key matches \(s.label)", "Compared public key material derived in memory."))
            } else if let c = r.cas.first(where: { $0.cert.publicKey.material == key.material }) {
                out.append(f("ipsec-key-\(k)", .warning, "keymatch", "Private key belongs to the CA \(c.label), not a server certificate", "Keep CA keys on pfSense only; never copy them to clients."))
            } else {
                out.append(f("ipsec-key-\(k)", .fail, "keymatch", "Private key does not match any certificate supplied", "Use the key generated with this certificate, or reissue in Cert. Manager."))
            }
        }
        r.findings = sort(out)
        return r
    }

    static func sort(_ f: [Finding]) -> [Finding] { f.sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity } }

    static func chain(for leaf: Certificate, pool: [IPsecEntry]) -> [Certificate] { ChainCheck.chain(for: leaf, pool: pool.map(\.cert)) }
    static func verify(_ chain: [Certificate], now: Date) -> (ok: Bool, message: String) { ChainCheck.verify(chain, now: now) }

    static func validity(_ c: Certificate, _ p: String, _ who: String, now: Date) -> Finding {
        let days = Int(c.notAfter.timeIntervalSince(now) / 86_400)
        if now < c.notBefore { return f(p + "valid", .fail, "validity", "\(who) is not yet valid", "Valid from \(Analysis.fmt(c.notBefore)). Check the firewall clock.") }
        if now > c.notAfter { return f(p + "valid", .fail, "validity", "\(who) expired \(Analysis.fmt(c.notAfter))", "Clients refuse expired certificates. Renew in Cert. Manager.") }
        if days <= Analysis.warnDays { return f(p + "valid", .warning, "validity", "\(who) expires in \(days) day\(days == 1 ? "" : "s")", "Expires \(Analysis.fmt(c.notAfter)). Renew now and update every Phase 1 that uses it.") }
        return f(p + "valid", .pass, "validity", "\(who) valid for \(days) more days", "Expires \(Analysis.fmt(c.notAfter)).")
    }

    static func keyFinding(_ c: Certificate, _ p: String, _ who: String) -> Finding {
        switch c.publicKey.algorithm {
        case .rsa(let b) where b < 2048: return f(p + "key", .fail, "reissue", "\(who) has a weak \(b)-bit RSA key", "IKEv2 clients on macOS/iOS and Windows need RSA 2048+ or ECDSA.")
        case .rsa(let b): return f(p + "key", .pass, "reissue", "\(who) key: RSA \(b)-bit")
        case .ec(let curve) where ["P-256", "P-384", "P-521"].contains(curve): return f(p + "key", .pass, "reissue", "\(who) key: ECDSA \(curve)", "Phase 1 authentication must be an ECDSA method when the certificate is ECDSA.")
        case .ec(let curve): return f(p + "key", .fail, "reissue", "\(who) uses unsupported curve \(curve)", "Use P-256 (prime256v1) or P-384 (secp384r1).")
        case .ed25519: return f(p + "key", .warning, "reissue", "\(who) uses Ed25519", "macOS/iOS and Windows IKEv2 clients do not accept Ed25519 certificates. Use RSA 2048+ or ECDSA P-256/P-384.")
        case .other(let o): return f(p + "key", .fail, "reissue", "\(who) uses an unsupported key algorithm", o)
        }
    }

    static func sigFinding(_ c: Certificate, _ p: String, _ who: String) -> Finding {
        if sha2Signatures.contains(c.signatureOID) { return f(p + "sig", .pass, "reissue", "\(who) signature: \(c.signatureAlgorithm)") }
        if c.signatureIsWeak { return f(p + "sig", .fail, "reissue", "\(who) is signed with \(c.signatureAlgorithm)", "SHA-1/MD5 signatures are rejected. Reissue with Digest Algorithm SHA256 or stronger.") }
        if c.signatureOID == pss { return f(p + "sig", .info, "reissue", "\(who) is signed with RSASSA-PSS", "Supported by current macOS and Windows; older clients may not accept it.") }
        return f(p + "sig", .warning, "reissue", "\(who) uses an unrecognised signature algorithm (\(c.signatureAlgorithm))")
    }

    static func evaluate(server s: IPsecEntry, index i: Int, label: String, pool: [IPsecEntry], phase1: [IPsecParse.P1], cas: [IPsecEntry], expected: String?, now: Date) -> [Finding] {
        let c = s.cert, p = "srv\(i)-", who = "\(label)Server certificate"
        var out: [Finding] = [validity(c, p, who, now: now), keyFinding(c, p, who), sigFinding(c, p, who)]
        if c.isCA == true { out.append(f(p + "isca", .fail, "reissue", "\(who) is a CA certificate", "Choose Certificate Type: Server Certificate when creating it, so Basic Constraints is CA:FALSE.")) }
        // Lifetime: Apple's documented TLS rule (HT210176, certs issued after 1 Jul 2019) is commonly enforced by macOS/iOS IKEv2 too.
        let lifetime = Int((c.notAfter.timeIntervalSince(c.notBefore) / 86_400).rounded(.down))
        if c.notBefore < appleRuleStart {
            out.append(f(p + "lifetime", .info, "reissue", "\(who) lifetime is \(lifetime) days (issued before 1 July 2019)", "Apple's 825-day limit applies only to certificates issued on or after 1 July 2019. Any replacement must be 825 days or fewer."))
        } else {
            out.append(lifetime > appleMaxDays
                ? f(p + "lifetime", .warning, "reissue", "\(who) lifetime is \(lifetime) days (over \(appleMaxDays))", "Apple limits server certificates issued on or after 1 July 2019 to 825 days for TLS, and macOS/iOS IKEv2 clients are reported to reject longer ones too. Reissue with Lifetime 825 or less.")
                : f(p + "lifetime", .pass, "reissue", "\(who) lifetime is \(lifetime) days (825 or fewer)"))
        }
        // EKU
        if let eku = c.extendedKeyUsage {
            out.append(eku.contains(OID.serverAuth)
                ? f(p + "eku", .pass, "reissue", "\(who) has the serverAuth EKU")
                : f(p + "eku", .fail, "reissue", "\(who) lacks the serverAuth EKU", "Present: \(eku.map(OID.name).joined(separator: ", ")). Windows and macOS/iOS IKEv2 clients require TLS Web Server Authentication (1.3.6.1.5.5.7.3.1).")) 
            out.append(eku.contains(ikeIntermediate)
                ? f(p + "eku-ike", .pass, "reissue", "\(who) has the IKE intermediate EKU (1.3.6.1.5.5.8.2.2)", "Used by Windows; harmless for macOS/iOS.")
                : f(p + "eku-ike", .info, "reissue", "\(who) has no IKE intermediate EKU (1.3.6.1.5.5.8.2.2)", "Recommended for Windows clients (pfSense's Server Certificate type adds it). macOS/iOS do not need it."))
        } else {
            out.append(f(p + "eku", .warning, "reissue", "\(who) has no Extended Key Usage", "Windows and macOS/iOS expect serverAuth; reissue as Certificate Type: Server Certificate (adds serverAuth and 1.3.6.1.5.5.8.2.2)."))
        }
        // keyUsage
        if let ku = c.keyUsageBits, let b0 = ku.first {
            out.append(b0 & 0x80 != 0 ? f(p + "ku", .pass, "reissue", "\(who) keyUsage includes digitalSignature")
                                      : f(p + "ku", .fail, "reissue", "\(who) keyUsage lacks digitalSignature", "IKEv2 AUTH payloads are signatures; the certificate must allow digitalSignature."))
        } else {
            out.append(f(p + "ku", .info, "reissue", "\(who) has no keyUsage extension", "Allowed by RFC 5280, but pfSense server certificates normally include digitalSignature and keyEncipherment."))
        }
        // SAN / identifier
        let names = c.dnsNames + c.ipAddresses
        if !c.hasSANExtension || names.isEmpty {
            out.append(f(p + "san", .fail, "san", "\(who) has no DNS or IP Subject Alternative Name", "Windows and macOS/iOS match the server address and Remote ID against the SAN, not the Common Name."))
        } else { out.append(f(p + "san", .pass, "san", "\(who) SAN: \(names.joined(separator: ", "))")) }
        if let id = expected?.trimmingCharacters(in: .whitespaces), !id.isEmpty {
            let m = c.matches(hostname: id)
            if m.matched && !m.viaCommonNameOnly {
                let wildcard = !c.dnsNames.contains { $0.lowercased() == id.lowercased() } && !c.ipAddresses.contains { Certificate.normalizeIP($0) == Certificate.normalizeIP(id) }
                out.append(wildcard ? f(p + "id", .info, "san", "\(who) covers \(id) only via a wildcard", "Some IKEv2 clients (notably Windows) handle wildcard server certificates poorly. Prefer the exact FQDN in the SAN.")
                                    : f(p + "id", .pass, "san", "\(who) covers the client identifier \(id)"))
            } else {
                out.append(f(p + "id", .fail, "san", "\(who) does not cover \(id)\(m.viaCommonNameOnly ? " (Common Name only)" : "")", "Clients connect to and verify \(id). Add it to the SAN as \(id.contains(":") || id.allSatisfy({ $0.isNumber || $0 == "." }) ? "an IP address" : "an FQDN") entry."))
            }
        } else {
            out.append(f(p + "id", .info, "san", "No client identifier given", "Pass the FQDN or IP clients use (Server / Remote ID) to confirm the SAN covers it."))
        }
        // Chain
        let ch = chain(for: c, pool: pool)
        if ch.count == 1 && !c.isSelfIssued {
            out.append(f(p + "chain", .fail, "chain", "\(who): issuing CA not supplied", "Issuer: \(c.issuer.text). Add the CA from System › Cert. Manager › CAs (certificate only)."))
        } else if c.isSelfIssued {
            out.append(f(p + "chain", .fail, "chain", "\(who) is self-signed", "Issue it from a CA in Cert. Manager; clients trust the CA, not individual server certificates."))
        } else {
            for (k, issuer) in ch.dropFirst().enumerated() where issuer.isCA != true {
                out.append(f(p + "chain-notca-\(k)", .fail, "chain", "\(label)Issuer \(issuer.displayName) is not marked as a CA", "Its Basic Constraints is \(issuer.isCA == false ? "CA:FALSE" : "missing"). Create the CA under System › Cert. Manager › CAs."))
            }
            for (k, issuer) in ch.enumerated() where k >= 1 && issuer.basicConstraintsMalformed {
                out.append(f(p + "chain-bcbad-\(k)", .fail, "chain", "\(label)\(issuer.displayName) has malformed basicConstraints", "The pathLenConstraint is negative or unreadable; clients reject such a CA. Reissue the CA certificate."))
            }
            for (k, issuer) in ch.enumerated() where k >= 1 && issuer.isCA == true {
                // RFC 5280 6.1.4: self-issued intermediates (e.g. CA re-key/rollover certificates) do not count toward pathLen.
                let below = ch[1..<k].filter { !$0.isSelfIssued }.count
                if let pl = issuer.pathLen, below > pl {
                    out.append(f(p + "chain-pathlen-\(k)", .fail, "chain", "\(label)\(issuer.displayName) allows \(pl) intermediate CA\(pl == 1 ? "" : "s") below it, but the chain has \(below)", "basicConstraints pathLenConstraint is violated; clients reject the chain. Self-issued intermediates are not counted. Issue the server certificate from a CA within the limit."))
                }
            }
            let v = verify(ch, now: now)
            out.append(v.ok ? f(p + "chain", .pass, "chain", "\(who) chain verifies to \(ch.last!.displayName)", ch.map(\.displayName).joined(separator: " → "))
                            : f(p + "chain", .fail, "chain", "\(who) chain does not verify", v.message))
            if let top = ch.last, !ChainCheck.isSelfSigned(top) { out.append(f(p + "chain-top", .warning, "chain", "\(label)Chain stops at \(top.displayName)", "Its issuer (\(top.issuer.text)) was not supplied; clients need the root CA installed.")) }
            if let ca = ch.dropFirst().first, ca.notAfter < c.notAfter { out.append(f(p + "ca-before", .warning, "chain", "\(label)CA \(ca.displayName) expires before the server certificate", "CA expires \(Analysis.fmt(ca.notAfter)); clients stop trusting the server certificate then.")) }
        }
        for p1 in phase1 {
            let role = p1.mobile ? "mobile clients" : "site-to-site"
            out.append(f(p + "p1-\(p1.index)", .info, "info", "Used by IPsec \(p1.descr) (\(role))"))
            if let caref = p1.caref, let ca = cas.first(where: { $0.refid == caref }), !ch.dropFirst().contains(where: { $0.sha256 == ca.cert.sha256 }) {
                out.append(f(p + "p1ca-\(p1.index)", .info, "chain", "\(p1.descr): Peer Certificate Authority \(ca.label) did not issue this server certificate",
                             p1.mobile ? "Mobile client certificates are validated against \(ca.label). That is normal when clients use a different CA; confirm it is intended."
                                       : "The remote peer's certificate is validated against \(ca.label). That is normal when each side has its own CA; confirm it is intended."))
            }
        }
        if let own = s.ownKey {
            out.append(own.material == c.publicKey.material ? f(p + "prv", .pass, "keymatch", "\(who) stored private key matches", "Compared in memory; the key is not shown.")
                                                            : f(p + "prv", .fail, "keymatch", "\(who) stored private key does not match the certificate", "Strongswan will fail to authenticate. Reissue the certificate in Cert. Manager."))
        }
        return out
    }

    static func evaluate(ca e: IPsecEntry, index i: Int, now: Date) -> [Finding] {
        let c = e.cert, p = "ca\(i)-", who = "CA \(e.label)"
        var out = [validity(c, p, who, now: now), keyFinding(c, p, who)]
        if !c.isSelfIssued { out.append(sigFinding(c, p, who)) }
        if c.basicConstraintsMalformed { out.append(f(p + "bc-bad", .fail, "chain", "\(who) has malformed basicConstraints", "Negative or unreadable pathLenConstraint.")) }
        out.append(c.isCA == true ? f(p + "bc", .pass, "chain", "\(who) has basicConstraints CA:TRUE")
                                  : f(p + "bc", .fail, "chain", "\(who) is missing basicConstraints CA:TRUE", "Clients will not accept it as an issuer."))
        if let ku = c.keyUsageBits, let b0 = ku.first, b0 & 0x04 == 0 { out.append(f(p + "ku", .fail, "chain", "\(who) keyUsage lacks keyCertSign")) }
        if e.ownKey != nil { out.append(f(p + "prv", .info, "keymatch", "\(who) private key is stored in this file", "Treat this config.xml as secret; it can issue trusted VPN certificates.")) }
        return out
    }
}

/// Copy-only guidance. Nothing here is executed by the app.
public enum IPsecAdvisor {
    public static let docs = [KB.pfSense, KB.pki, KB.runbook]
    public static func guidance(for f: Finding, platform: Platform, identifier: String? = nil) -> [Guidance] {
        let id = identifier.flatMap { Target.validHost($0) ? $0 : nil } ?? AppConfig.current.vpnHostPlaceholder
        let pf: [String]
        switch f.kind {
        case "chain": pf = ["System › Cert. Manager › CAs: confirm the issuing CA exists and is a CA. Export its certificate (not the key) for clients.", "VPN › IPsec › Mobile Clients / Phase 1: set My Certificate to the server certificate and Peer Certificate Authority to the CA that issued the client side.", "Save and Apply Changes, then reconnect a test client."]
        case "keymatch": pf = ["The stored key must be the one generated with the certificate. If you imported the certificate, re-import it with its matching key, otherwise reissue it (System › Cert. Manager › Certificates › Add/Sign).", "Never export the CA or server private key to clients."]
        default: pf = ["System › Cert. Manager › Certificates › Add/Sign: Method Create an internal Certificate, signed by the VPN CA.", "Key type RSA 2048+ (or ECDSA prime256v1/secp384r1), Digest SHA256, Lifetime 825 days or fewer.", "Common Name and Alternative Names: the FQDN (type FQDN) or IP (type IP address) that clients use as Server / Remote ID.", "Certificate Type: Server Certificate (adds serverAuth and the IKE intermediate EKU 1.3.6.1.5.5.8.2.2).", "VPN › IPsec › Phase 1 for mobile clients: select the new certificate as My Certificate, Save, Apply Changes."]
        }
        let pfSense = Guidance(title: "pfSense Cert. Manager", steps: pf + ["Run the commands below on the firewall in Diagnostics › Command Prompt, or an SSH shell (menu option 8)."],
                               commands: ["swanctl --list-certs", "for f in /var/etc/ipsec/swanctl/x509/*.crt; do openssl x509 -in \"$f\" -noout -subject -enddate -ext subjectAltName,extendedKeyUsage,keyUsage; done"], docs: docs)
        let windows = Guidance(title: "Windows IKEv2 client (PowerShell as administrator)", steps: [
            "Import the CA into Local Computer › Trusted Root Certification Authorities, not the current user store (error 13801 otherwise).",
            "The VPN server address must match a SAN in the server certificate (errors 13801/13806 point at the certificate).",
            "Replace the file names and connection name below before running. If no client identifier was entered, or it is not a valid host name or IP, the commands use the placeholder \(AppConfig.current.vpnHostPlaceholder).",
            "Optional: Set-VpnConnectionIPsecConfiguration pins Windows' IKE/ESP proposals. Run it only if the values match the pfSense Phase 1/Phase 2 settings, otherwise the tunnel will not negotiate."],
            commands: ["Import-Certificate -FilePath .\\vpn-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root", "certutil -verify .\\vpn-server.crt", "Add-VpnConnection -Name 'IKEv2 VPN' -ServerAddress '\(id)' -TunnelType Ikev2 -AuthenticationMethod Eap -EncryptionLevel Required", "Set-VpnConnectionIPsecConfiguration -ConnectionName 'IKEv2 VPN' -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -PfsGroup PFS2048 -Force", "Get-VpnConnection -Name 'IKEv2 VPN'"], docs: [])
        let mac = Guidance(title: "macOS / iOS configuration profile", steps: [
            "Install the CA certificate (not the key): on macOS add it to the System keychain and set Always Trust, or include it in the profile as a certificate payload.",
            "In the profile's IKEv2 payload, RemoteAddress and RemoteIdentifier must both be a SAN of the server certificate (\(id); \(AppConfig.current.vpnHostPlaceholder) is a placeholder used when no valid identifier was entered); set ServerCertificateIssuerCommonName to the CA's Common Name.",
            "Reinstall the profile in System Settings › General › Device Management. If you keep a reference profile, open it in a text editor; double-clicking a .mobileconfig starts installation."],
            commands: ["security verify-cert -c vpn-server.crt -r vpn-ca.crt -p IPSec", "\(Shell.openssl) x509 -in vpn-server.crt -noout -subject -dates -ext subjectAltName,extendedKeyUsage,keyUsage"], docs: [])
        switch platform {
        case .macOS: return [mac, pfSense, windows]
        case .windowsAD, .windowsIIS: return [windows, pfSense, mac]
        default: return [pfSense, windows, mac]
        }
    }
}
