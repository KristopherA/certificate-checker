import Security
import Foundation

// MARK: Munki, FileMaker Server, Retrospect, HP printer EWS and Barracuda WAF (0.8.0).
// One TLS handshake per check; trust evaluation never fetches intermediates. Guidance is copy-only.
// Default-certificate detection is by subject/issuer naming only; it was built from SYNTHETIC look-alikes and is untested against real products.

public enum Vendor {
    static func names(_ c: Certificate) -> String {
        [c.subject.commonName ?? "", Appliance.org(c.subject), c.issuer.commonName ?? "", Appliance.org(c.issuer)].joined(separator: " ")
    }
    static func has(_ c: Certificate, _ words: [String]) -> Bool { let n = names(c); return words.contains { n.localizedCaseInsensitiveContains($0) } }
    /// FileMaker Server's bundled default certificate (named "FileMaker", or issued by the FileMaker / Claris test CA). It does not verify the server name.
    public static func isFileMakerDefault(_ leaf: Certificate) -> Bool {
        (leaf.subject.commonName ?? "").lowercased() == "filemaker" || (has(leaf, ["FileMaker", "Claris International"]) && !leaf.subject.text.localizedCaseInsensitiveContains("."))
    }
    /// HP printers ship a self-signed certificate with O=HP / Hewlett-Packard / HP Inc., or a CN of "HP" followed by a non-letter (e.g. "HP LaserJet",
    /// "HP_1A2B3C"), or the NPI + hex printer name. A bare "HP" prefix is not enough: hpc01, HPE…, hpux… are not HP printer defaults.
    public static func isHPDefault(_ leaf: Certificate) -> Bool {
        guard leaf.isSelfIssued else { return false }
        // Compare each O value on its own: Appliance.org joins O and OU, so "HP Inc." + OU would never match exactly.
        let orgs = [leaf.subject, leaf.issuer].flatMap { $0.attributes.filter { $0.0 == "2.5.4.10" }.map { $0.1.trimmingCharacters(in: .whitespaces).lowercased() } }
        let hpOrg = orgs.contains { $0 == "hp" || $0 == "hp inc." || $0 == "hp inc" || $0.hasPrefix("hewlett-packard") || $0.hasPrefix("hewlett packard") }
        return hpOrg || isHPName(leaf.subject.commonName ?? "")
    }
    static func isHPName(_ cn: String) -> Bool {
        let u = cn.uppercased()
        if u == "HP" { return true }
        if u.hasPrefix("HP-UX") { return false }
        if u.hasPrefix("HP"), let next = u.dropFirst(2).first, !next.isLetter { return true }
        if u.hasPrefix("NPI") { let rest = u.dropFirst(3); return rest.count >= 6 && rest.allSatisfy { $0.isHexDigit } }
        return false
    }
    /// Barracuda appliances serve a factory self-signed certificate naming Barracuda until a certificate is uploaded.
    public static func isBarracudaDefault(_ leaf: Certificate) -> Bool { leaf.isSelfIssued && has(leaf, ["Barracuda"]) }
    public static func isRetrospectDefault(_ leaf: Certificate) -> Bool { leaf.isSelfIssued && has(leaf, ["Retrospect"]) }
    /// Placeholder certificates any web server can end up with: OpenSSL's sample subject, CN localhost, Debian snakeoil.
    public static func isGenericDefault(_ leaf: Certificate) -> Bool {
        let cn = (leaf.subject.commonName ?? "").lowercased()
        return leaf.isSelfIssued && (cn == "localhost" || cn == "localhost.localdomain" || has(leaf, ["Internet Widgits Pty Ltd", "snakeoil"]))
    }

    public static func adjust(_ findings: [Finding], chain: [Certificate], target: Target, tlsVersion: String?, now: Date = Date()) -> [Finding] {
        guard let leaf = chain.first, target.service.isVendor else { return findings }
        var out = findings
        func downgradeTrust(_ note: String) {
            guard let i = out.firstIndex(where: { $0.id == "trust" }), out[i].severity == .fail,
                  leaf.notBefore <= now, now <= leaf.notAfter, ChainCheck.verify(chain, now: now).ok else { return }
            out[i].severity = .warning; out[i].detail += " " + note
        }
        func add(_ id: String, _ s: Severity, _ title: String, _ detail: String, _ kind: String) { out.append(Finding(id, s, .vendor, title, detail, kind: kind)) }
        let product = target.service.rawValue.replacingOccurrences(of: " (HTTPS)", with: "").replacingOccurrences(of: " (TLS)", with: "")
        add("vendor-fp", .info, "Presented certificate SHA-256 fingerprint \(leaf.sha256)", "\(product) on \(target.endpoint). Shown for comparison only.", "fingerprint")
        let unverified = "Identity is unverified: compare the SHA-256 fingerprint shown here with the one on the device before trusting it."
        switch target.service {
        case .fileMaker:
            if isFileMakerDefault(leaf) {
                add("fms-default", .fail, "FileMaker Server default certificate", "\(leaf.displayName), issued by \(leaf.issuer.commonName ?? leaf.issuer.text). Claris supports it for testing only; it does not verify the server name, so FileMaker Pro/Go show an unverified connection and the Data API / WebDirect clients reject it. Import a CA-issued certificate in Admin Console.", "fms-cert")
            } else if leaf.isSelfIssued {
                add("fms-selfsigned", .warning, "FileMaker Server presents a self-signed certificate", "Clients cannot verify it. Import a CA-issued certificate for the server's DNS name.", "fms-cert")
            }
            if target.port == 5003 { add("fms-5003", .info, "Checked the FileMaker client port 5003", "FileMaker Pro/Go use 5003 (or 443 with HTTPS tunneling); Admin Console, WebDirect and the Data API use 443. Both serve the same certificate.", "") }
        case .retrospectConsole:
            add("retro-scope", .info, "Checked the Retrospect web console only", "The Retrospect Engine (TCP 22024) and Retrospect Clients (TCP/UDP 497) use Retrospect's own protocol, not standard TLS, so there is no certificate to check there. The hosted Management Console is Retrospect's own service; this check is for a self-hosted web console such as Retrospect Virtual (443 or 8443).", "")
            if isRetrospectDefault(leaf) || isGenericDefault(leaf) {
                add("retro-default", .warning, "Retrospect console default certificate", "\(leaf.displayName) is self-signed. Browsers warn and cannot verify the console. \(unverified)", "retro-cert"); downgradeTrust("Expected for the console's default self-signed certificate.")
            } else if leaf.isSelfIssued { add("retro-selfsigned", .warning, "Retrospect console presents a self-signed certificate", "Install a CA-issued certificate for the console name.", "retro-cert") }
        case .hpPrinter:
            if isHPDefault(leaf) {
                add("hp-default", .warning, "HP printer factory self-signed certificate", "\(leaf.displayName). Browsers warn and nothing ties it to this printer. Install a CA-issued certificate (or a CSR signed by your CA) in the EWS. \(unverified)", "hp-cert"); downgradeTrust("Expected for the HP factory self-signed certificate.")
            } else if leaf.isSelfIssued { add("hp-selfsigned", .warning, "HP printer presents a self-signed certificate", "Install a CA-issued certificate in the EWS.", "hp-cert") }
            if case .rsa(let bits) = leaf.publicKey.algorithm, bits < 2048 {
                add("hp-weakkey", .fail, "HP printer certificate uses a \(bits)-bit RSA key", "Older HP firmware generates 1024-bit keys. Create a new 2048-bit certificate or CSR in the EWS (firmware updates may be needed).", "hp-tls")
            }
            if let v = tlsVersion, v == "TLS 1.0" || v == "TLS 1.1" {
                add("hp-protocol", .fail, "HP printer negotiated \(v)", "Disable TLS 1.0/1.1 in the EWS encryption settings.", "hp-tls")
            } else {
                add("hp-protocol", .info, "Older protocols not tested", "One handshake: only the negotiated version\(tlsVersion.map { " (\($0))" } ?? "") is known. Whether the printer still accepts TLS 1.0/1.1 needs the copy-only openssl -tls1 / -tls1_1 commands in the guidance.", "hp-tls")
            }
        case .barracudaService, .barracudaManagement:
            let mgmt = target.service == .barracudaManagement
            if isBarracudaDefault(leaf) {
                add("waf-default", mgmt ? .warning : .fail, "Barracuda factory self-signed certificate on the \(mgmt ? "management UI" : "service listener")",
                    mgmt ? "Administrators cannot verify the management interface. Upload a CA-issued certificate for the management UI. \(unverified)" : "Clients of this published service get a certificate warning. Upload or create a trusted certificate and assign it to the HTTPS service.", "waf-cert")
                if mgmt { downgradeTrust("Expected for the Barracuda factory management certificate.") }
            } else if leaf.isSelfIssued { add("waf-selfsigned", mgmt ? .warning : .fail, "Barracuda \(mgmt ? "management UI" : "service") presents a self-signed certificate", "Assign a CA-issued certificate.", "waf-cert") }
            if !mgmt && target.port == 8443 { add("waf-port", .info, "Port 8443 is usually the management UI", "Use the management check (waf-mgmt) for 8443.", "") }
        case .munkiRepo:
            if isGenericDefault(leaf) { add("munki-default", .fail, "Munki repo serves a placeholder certificate", "\(leaf.displayName) is a self-signed web-server default. Munki clients reject it unless SoftwareRepoCACertificate trusts it. Install a certificate for the repo name.", "munki-cert") }
            else if leaf.isSelfIssued { add("munki-selfsigned", .warning, "Munki repo presents a self-signed certificate", "Munki clients accept it only when SoftwareRepoCACertificate names it.", "munki-cert") }
        default: break
        }
        return out.sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity }
    }

    /// Explains a failed handshake on ports that are not TLS.
    public static func handshakeFailureNote(_ t: Target) -> Finding? {
        if t.service == .retrospectConsole && [22024, 497].contains(t.port) {
            return Finding("retro-port", .info, .vendor, "Port \(t.port) is not a TLS port", "Retrospect Engine (22024) and Client (497) use Retrospect's own protocol; no certificate can be checked there. Check the web console port instead.")
        }
        if t.service == .fileMaker && t.port == 5003 {
            return Finding("fms-port", .info, .vendor, "FileMaker 5003 did not complete TLS", "FileMaker Server uses TLS on 5003 only when database connections use SSL (Admin Console › Configuration › SSL Certificate). Check 443 as well.")
        }
        return nil
    }
}

// MARK: Munki ManagedInstalls (offline; keys in memory only)

public struct MunkiSettings: Equatable {
    public var repoURL: String?, useClientCertificate = false, clientCertificatePath: String?, clientKeyPath: String?, caCertificate: String?, caPath: String?
    public var repoHost: String? { repoURL.flatMap { URLComponents(string: $0)?.host } }
    public var repoPort: Int { repoURL.flatMap { URLComponents(string: $0) }.map { $0.port ?? ($0.scheme?.lowercased() == "http" ? 80 : 443) } ?? 443 }
    public var repoIsHTTPS: Bool { repoURL.flatMap { URLComponents(string: $0)?.scheme?.lowercased() } == "https" }
    public var repoTarget: Target? {
        guard repoIsHTTPS, let h = repoHost, !h.isEmpty else { return nil }
        return Target(name: "Munki repo \(h)", host: h, port: repoPort, service: .munkiRepo, platform: .munki)
    }
}

public enum Munki {
    /// Parses a ManagedInstalls plist (XML or binary) from /Library/Preferences. Configuration profiles can override it; that is not visible here.
    public static func parse(_ data: Data) throws -> MunkiSettings {
        guard data.count <= FileCheck.maxFileSize else { throw CheckError.message("Plist is larger than 2 MB.") }
        guard let d = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { throw CheckError.message("Not a ManagedInstalls property list.") }
        func s(_ k: String) -> String? { (d[k] as? String).flatMap { $0.trimmingCharacters(in: .whitespaces).isEmpty ? nil : $0 } }
        var m = MunkiSettings()
        m.repoURL = s("SoftwareRepoURL"); m.useClientCertificate = (d["UseClientCertificate"] as? Bool) ?? false
        m.clientCertificatePath = s("ClientCertificatePath"); m.clientKeyPath = s("ClientKeyPath")
        m.caCertificate = s("SoftwareRepoCACertificate"); m.caPath = s("SoftwareRepoCAPath")
        return m
    }

    /// Reads a ManagedInstalls plist: regular files only (symlinks refused, not followed), at most 2 MB, read in memory.
    public static func load(_ url: URL) throws -> MunkiSettings {
        let a = try FileManager.default.attributesOfItem(atPath: url.path)
        guard (a[.type] as? FileAttributeType) == .typeRegular else { throw CheckError.message("Not a regular file (symbolic links are not followed).") }
        guard ((a[.size] as? NSNumber)?.intValue ?? 0) <= FileCheck.maxFileSize else { throw CheckError.message("Plist is larger than 2 MB.") }
        return try parse(Data(contentsOf: url, options: .uncached))
    }
    /// Sorts override files into certificate and key by content (a PEM "PRIVATE KEY" block), not by selection order. At most one of each.
    public static func classifyOverrides(_ urls: [URL]) throws -> (cert: URL?, key: URL?) {
        var cert: URL?, key: URL?
        for u in urls {
            let a = try FileManager.default.attributesOfItem(atPath: u.path)
            guard (a[.type] as? FileAttributeType) == .typeRegular, ((a[.size] as? NSNumber)?.intValue ?? 0) <= FileCheck.maxFileSize else { throw CheckError.message("\(u.lastPathComponent): not a regular file of at most 2 MB.") }
            let data = try Data(contentsOf: u, options: .uncached)
            let text = String(decoding: data, as: UTF8.self)
            let pemKey = text.contains("PRIVATE KEY-----"), pemCert = text.contains("CERTIFICATE-----")
            if pemKey && pemCert { throw CheckError.message("\(u.lastPathComponent) holds both a certificate and a private key. Select them as separate files.") }
            // DER (no PEM armour): a file that parses as an X.509 certificate is a certificate, anything else is treated as a key.
            let isKey = pemKey || (!pemCert && !text.contains("-----BEGIN") && SecCertificateCreateWithData(nil, data as CFData) == nil)
            if isKey {
                guard key == nil else { throw CheckError.message("More than one private key selected.") }; key = u
            } else {
                guard cert == nil else { throw CheckError.message("More than one certificate file selected.") }; cert = u
            }
        }
        return (cert, key)
    }
    public static let profileNote = "Configuration-profile (MDM) values for ManagedInstalls are not read; only the plist file is checked, and a profile can override any of these settings."

    public static func settingsFindings(_ m: MunkiSettings) -> [Finding] {
        func f(_ id: String, _ s: Severity, _ t: String, _ d: String = "") -> Finding { Finding(id, s, .vendor, t, d, kind: "munki-config") }
        var out: [Finding] = [f("munki-profiles", .info, "Configuration-profile values not read", profileNote)]
        if let u = m.repoURL {
            if m.repoIsHTTPS { out.append(f("munki-url", .pass, "SoftwareRepoURL uses HTTPS", u)) }
            else { out.append(f("munki-url", .fail, "SoftwareRepoURL is not HTTPS", "\(u): catalogs, manifests and packages travel unencrypted and client certificates are never used.")) }
        } else { out.append(f("munki-url", .warning, "SoftwareRepoURL not set", "Munki falls back to http://munki/repo. It may be set by a configuration profile instead.")) }
        if m.caCertificate == nil { out.append(f("munki-ca", .info, "SoftwareRepoCACertificate not set", m.caPath != nil ? "SoftwareRepoCAPath is set (a folder); this check reads a single CA file. Supply one with --ca." : "The repo certificate must chain to a CA in the System keychain.")) }
        if m.useClientCertificate {
            if m.clientCertificatePath == nil { out.append(f("munki-clientcert", .warning, "UseClientCertificate is true but ClientCertificatePath is not set", "Munki then looks in <ManagedInstallDir>/certs. Supply the certificate with --cert to check it.")) }
        } else if m.clientCertificatePath != nil || m.clientKeyPath != nil {
            out.append(f("munki-clientcert", .warning, "Client certificate paths set but UseClientCertificate is false", "Munki does not present the client certificate until UseClientCertificate is true."))
        }
        return out
    }

    /// Validates the client certificate/key pair against the repo CA. Paths come from the plist or from overrides; files ≤ 2 MB, read in memory.
    public static func inspect(_ m: MunkiSettings, cert: URL?, key: URL?, ca: URL?, now: Date = Date()) -> (chain: [Certificate], findings: [Finding]) {
        let certURL = cert ?? m.clientCertificatePath.map { URL(fileURLWithPath: $0) }
        let keyURL = key ?? m.clientKeyPath.map { URL(fileURLWithPath: $0) }
        let caURL = ca ?? m.caCertificate.map { URL(fileURLWithPath: $0) }
        var out = settingsFindings(m)
        guard let c = certURL else {
            if m.useClientCertificate { out.append(Finding("munki-pair", .info, .vendor, "Client certificate not checked", "No certificate path to read.")) }
            return ([], Stack.sort(out))
        }
        let r = MTLSPair.inspect([c] + (keyURL.map { [$0] } ?? []), ca: caURL.map { [$0] } ?? [], now: now, context: .munki)
        let pair = r.findings.map { f -> Finding in var g = f; if g.topic == .stack { g.topic = .vendor; g.kind = "munki-config" }; return g }
        return (r.chain, Stack.sort(out + pair))
    }
}

// MARK: Copy-only guidance

public enum VendorAdvisor {
    public static func munki(host: String, why: String? = nil) -> Guidance {
        let h = Shell.quote("https://\(host)/repo/catalogs/all")
        return Guidance(title: "Munki: repo certificate and client certificates", steps: [why,
            "Repo server: install a certificate for the repo DNS name with its full chain on the web server hosting the repo.",
            "Private CA: copy the CA certificate to each client and point SoftwareRepoCACertificate at it (configuration profile or /Library/Preferences/ManagedInstalls).",
            "Client certificates: set UseClientCertificate, ClientCertificatePath and ClientKeyPath (key readable by root only, mode 600). Certificates need the clientAuth EKU.",
            "Then run a check-only Munki run on one client."].compactMap { $0 },
            commands: ["sudo defaults read /Library/Preferences/ManagedInstalls",
                       "sudo defaults write /Library/Preferences/ManagedInstalls SoftwareRepoCACertificate '/Library/Managed Installs/certs/ca.pem'",
                       "sudo defaults write /Library/Preferences/ManagedInstalls UseClientCertificate -bool true",
                       "sudo defaults write /Library/Preferences/ManagedInstalls ClientCertificatePath '/Library/Managed Installs/certs/client.pem'",
                       "sudo defaults write /Library/Preferences/ManagedInstalls ClientKeyPath '/Library/Managed Installs/certs/client.key'",
                       "sudo chmod 600 '/Library/Managed Installs/certs/client.key'",
                       "\(Shell.openssl) verify -CAfile ca.pem -purpose sslclient client.pem",
                       "sudo curl -sS -o /dev/null -w '%{http_code}\\n' --cacert ca.pem --cert client.pem --key client.key \(h)",
                       "sudo managedsoftwareupdate --checkonly -v"],
            docs: [KB.pki])
    }
    public static func fileMaker(host: String, why: String? = nil) -> Guidance {
        Guidance(title: "FileMaker Server: import a custom certificate", steps: [why,
            "Admin Console › Configuration › SSL Certificate › Import Custom Certificate: the signed certificate, the private key (from the CSR step) and the intermediate bundle.",
            "Or create the CSR on the server with fmsadmin, have the CA sign it, then import. Restart the Database Server to load it.",
            "Connect clients by the DNS name on the certificate (not the IP) so FileMaker Pro/Go show a verified connection."].compactMap { $0 },
            commands: ["fmsadmin certificate create \(Shell.quote("/CN=" + host))",
                       "fmsadmin certificate import /path/to/signed.crt --intermediateCA /path/to/intermediate.crt",
                       "fmsadmin restart server",
                       "\(Shell.openssl) s_client -connect \(Shell.quote(host + ":5003")) -servername \(Shell.quote(host)) </dev/null | \(Shell.openssl) x509 -noout -subject -issuer -enddate"],
            docs: [KB.pki])
    }
    public static func retrospect(host: String, why: String? = nil) -> Guidance {
        Guidance(title: "Retrospect: web console certificate", steps: [why,
            "Only a self-hosted web console (for example Retrospect Virtual on 443 or 8443) uses a TLS certificate. Replace it with a CA-issued certificate for the console name, following that product's certificate settings, or publish the console behind a reverse proxy that has one.",
            "The Engine (22024) and Clients (497) use Retrospect's own encrypted protocol: there is no X.509 certificate to replace there."].compactMap { $0 },
            commands: ["\(Shell.openssl) s_client -connect \(Shell.quote(host + ":443")) -servername \(Shell.quote(host)) </dev/null | \(Shell.openssl) x509 -noout -subject -issuer -enddate",
                       "nc -vz \(Shell.quote(host)) 22024   # reachability only: not TLS"],
            docs: [KB.pki, KB.reverseProxy])
    }
    public static func hp(host: String, why: String? = nil) -> Guidance {
        let hp = Shell.quote(host + ":443")
        return Guidance(title: "HP printer EWS: certificate, key size and protocols", steps: [why,
            "Open the EWS (https://printer) › Security (or Networking) › Certificate Management: create a CSR with a 2048-bit key, have your CA sign it, then install the signed certificate. Menu names vary by model and firmware.",
            "Encryption / Mgmt. Protocols settings: disable TLS 1.0 and 1.1 and weak ciphers; update the firmware if those options are missing.",
            "Each openssl command below makes one handshake offering only that version: 'handshake failure' or 'no protocols available' means it is refused (good)."].compactMap { $0 },
            commands: ["\(Shell.openssl) s_client -connect \(hp) -tls1 </dev/null",
                       "\(Shell.openssl) s_client -connect \(hp) -tls1_1 </dev/null",
                       "\(Shell.openssl) s_client -connect \(hp) </dev/null | \(Shell.openssl) x509 -noout -subject -enddate -text | grep 'Public-Key'"],
            docs: [KB.pki])
    }
    public static func barracuda(host: String, management: Bool, why: String? = nil) -> Guidance {
        Guidance(title: management ? "Barracuda WAF: management UI certificate" : "Barracuda WAF: service certificate", steps: [why,
            "BASIC › Certificates: upload the signed certificate with its key and intermediates (PKCS#12 or PEM), or create a CSR there and upload the CA-signed result. Menu names vary by firmware.",
            management ? "ADVANCED › Secure Administration: select the uploaded certificate for the web interface (HTTPS on 8443) and save." : "BASIC › Services › Edit the HTTPS service › Certificate: select the uploaded certificate (and SNI certificates per domain), then save.",
            "Re-check the listener and the management port here."].compactMap { $0 },
            commands: ["\(Shell.openssl) s_client -connect \(Shell.quote(host + (management ? ":8443" : ":443"))) -servername \(Shell.quote(host)) -showcerts </dev/null"],
            docs: [KB.pki])
    }
    public static func binding(_ s: Service?, host: String, why: String?) -> Guidance? {
        switch s {
        case .munkiRepo: return munki(host: host, why: why)
        case .fileMaker: return fileMaker(host: host, why: why)
        case .retrospectConsole: return retrospect(host: host, why: why)
        case .hpPrinter: return hp(host: host, why: why)
        case .barracudaService: return barracuda(host: host, management: false, why: why)
        case .barracudaManagement: return barracuda(host: host, management: true, why: why)
        default: return nil
        }
    }
    public static func guidance(for f: Finding, target: Target?) -> [Guidance] {
        let host = target?.verifyName ?? AppConfig.current.hostPlaceholder
        switch f.kind {
        case "munki-cert", "munki-config": return f.severity >= .warning ? [munki(host: host)] : []
        case "fms-cert": return [fileMaker(host: host)]
        case "retro-cert": return [retrospect(host: host)]
        case "hp-cert", "hp-tls": return [hp(host: host)]
        case "waf-cert": return [barracuda(host: host, management: target?.service == .barracudaManagement)]
        case "fingerprint": return target.flatMap { binding($0.service, host: host, why: nil) }.map { [$0] } ?? []
        default: return []
        }
    }
}

/// Form state of the app's Services & devices pane, kept in Core so it can be unit tested.
public struct VendorForm: Equatable {
    public var host = "", service: Service = .fileMaker, port = "443", expected = ""
    public init() {}
    public static let services: [Service] = [.fileMaker, .retrospectConsole, .hpPrinter, .barracudaService, .barracudaManagement, .munkiRepo]
    public mutating func select(_ s: Service) { service = s; port = String(s.defaultPort) }
    public var canRun: Bool { !host.trimmingCharacters(in: .whitespaces).isEmpty }
    public var target: Target {
        let h = host.trimmingCharacters(in: .whitespaces)
        return Target(name: h, host: h, port: Int(port.trimmingCharacters(in: .whitespaces)) ?? -1, service: service,
                      expectedName: expected.trimmingCharacters(in: .whitespaces), platform: service.defaultPlatform ?? .generic)
    }
}
