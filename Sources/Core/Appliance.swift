import Foundation

// MARK: Synology DSM (5001), Proxmox VE (8006), Proxmox Backup Server (8007). TLS handshake only: no HTTP request, no login.

/// SHA-256 certificate fingerprint pins in the colon-hex form PBS clients use (AA:BB:…, 32 bytes).
public enum FingerprintPin {
    /// Normalises a user-supplied pin to upper-case colon-hex. Accepts colon-separated or plain hex (64 digits); nil otherwise.
    public static func normalize(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.count <= 200 else { return nil }
        let parts = t.contains(":") ? t.split(separator: ":", omittingEmptySubsequences: false).map(String.init) : stride(from: 0, to: t.count, by: 2).map { i -> String in
            let a = t.index(t.startIndex, offsetBy: i), b = t.index(a, offsetBy: min(2, t.count - i)); return String(t[a..<b]) }
        guard parts.count == 32, parts.allSatisfy({ $0.count == 2 && $0.allSatisfy(\.isHexDigit) }) else { return nil }
        return parts.map { $0.uppercased() }.joined(separator: ":")
    }
}

public enum Appliance {
    static func org(_ n: DistinguishedName) -> String { n.attributes.filter { $0.0 == "2.5.4.10" || $0.0 == "2.5.4.11" }.map(\.1).joined(separator: " ") }
    /// Synology's factory certificate: CN "synology", issued by the "Synology Inc. CA" the NAS generates.
    public static func isSynologyDefault(_ leaf: Certificate) -> Bool {
        (leaf.subject.commonName ?? "").lowercased() == "synology" || org(leaf.issuer).localizedCaseInsensitiveContains("Synology") || (leaf.issuer.commonName ?? "").localizedCaseInsensitiveContains("Synology")
    }
    /// The node certificate pve-cluster issues from its own "Proxmox Virtual Environment" / "PVE Cluster Manager CA".
    public static func isPVEDefault(_ leaf: Certificate) -> Bool {
        let i = (leaf.issuer.commonName ?? "") + " " + org(leaf.issuer)
        return i.localizedCaseInsensitiveContains("Proxmox Virtual Environment") || i.localizedCaseInsensitiveContains("PVE Cluster Manager CA")
    }
    /// PBS generates a self-signed certificate at install time.
    public static func isPBSDefault(_ leaf: Certificate) -> Bool { leaf.isSelfIssued && leaf.isCA != true }

    public static func adjust(_ findings: [Finding], chain: [Certificate], target: Target, now: Date = Date()) -> [Finding] {
        guard let leaf = chain.first, target.service.isAppliance else { return findings }
        var out = findings
        func downgradeTrust(_ note: String, to sev: Severity = .warning) {
            // Only when the trust failure is explained by the default CA/self-signed setup: inside validity, signatures verify.
            guard let i = out.firstIndex(where: { $0.id == "trust" }), out[i].severity == .fail,
                  leaf.notBefore <= now, now <= leaf.notAfter, ChainCheck.verify(chain, now: now).ok else { return }
            out[i].severity = sev; out[i].detail += " " + note
        }
        let product = target.service.rawValue.replacingOccurrences(of: " (HTTPS)", with: "")
        out.append(Finding("appl-fp", .info, .appliance, "Presented certificate SHA-256 fingerprint \(leaf.sha256)", "\(product) on \(target.endpoint). Shown for comparison only.", kind: "fingerprint"))
        switch target.service {
        case .synologyDSM:
            if isSynologyDefault(leaf) {
                out.append(Finding("dsm-default", .warning, .appliance, "Synology DSM factory certificate", "\(leaf.displayName), issued by \(leaf.issuer.commonName ?? leaf.issuer.text). Browsers and Hyper Backup / Drive clients warn. Replace it with a CA-issued or Let's Encrypt certificate and assign it to DSM.", kind: "dsm-cert"))
                downgradeTrust("Expected for the DSM factory certificate.")
            } else if leaf.isSelfIssued {
                out.append(Finding("dsm-selfsigned", .warning, .appliance, "Synology DSM presents a self-signed certificate", "Clients cannot verify it. Assign a CA-issued certificate to DSM.", kind: "dsm-cert"))
            }
        case .proxmoxVE:
            if isPVEDefault(leaf) {
                out.append(Finding("pve-default", .warning, .appliance, "Proxmox VE default node certificate (cluster CA)", "Issued by \(leaf.issuer.commonName ?? leaf.issuer.text), the cluster's own CA, which browsers do not trust. Install a custom certificate or use the built-in ACME client; pveproxy then serves it from pveproxy-ssl.pem.", kind: "pve-cert"))
                downgradeTrust("Expected for the default PVE cluster-CA certificate.")
            } else if leaf.isSelfIssued {
                out.append(Finding("pve-selfsigned", .warning, .appliance, "Proxmox VE presents a self-signed certificate", "Clients cannot verify it. Install a CA-issued certificate or use ACME.", kind: "pve-cert"))
            }
        case .proxmoxBackup:
            let selfSigned = isPBSDefault(leaf)
            if selfSigned { out.append(Finding("pbs-selfsigned", .info, .appliance, "Proxmox Backup Server self-signed certificate (default)", "PVE and proxmox-backup-client trust it only through a pinned SHA-256 fingerprint.", kind: "pbs-cert")) }
            if let raw = target.fingerprintPin, !raw.trimmingCharacters(in: .whitespaces).isEmpty {
                if let pin = FingerprintPin.normalize(raw) {
                    if pin == leaf.sha256 {
                        out.append(Finding("pbs-pin", .pass, .appliance, "Fingerprint pin matches the served certificate", pin, kind: "pbs-pin"))
                        if selfSigned { downgradeTrust("Trusted by the matching fingerprint pin, as PBS clients do.", to: .info) }
                    } else {
                        out.append(Finding("pbs-pin", .fail, .appliance, "Fingerprint pin does NOT match the served certificate", "Pinned \(pin), served \(leaf.sha256). PBS regenerated or replaced its certificate, or something else answers on \(target.endpoint). Confirm on the PBS host before updating the pin.", kind: "pbs-pin"))
                    }
                } else {
                    out.append(Finding("pbs-pin", .fail, .appliance, "Fingerprint pin is not a SHA-256 colon-hex value", "Expected 32 bytes as AA:BB:… (64 hex digits). Copy it from proxmox-backup-manager cert info or the PBS dashboard › Show Fingerprint.", kind: "pbs-pin"))
                }
            } else if selfSigned {
                out.append(Finding("pbs-pin", .warning, .appliance, "No fingerprint pin given for a self-signed PBS certificate", "Supply the fingerprint from the PBS host to verify this is the expected server.", kind: "pbs-pin"))
                downgradeTrust("Expected for the PBS default self-signed certificate; verify with a fingerprint pin.")
            }
        default: break
        }
        return out.sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity }
    }
}

// MARK: Copy-only guidance

public enum ApplianceAdvisor {
    public static func dsm(why: String? = nil) -> Guidance {
        Guidance(title: "Synology DSM: replace and assign the certificate", steps: [why,
            "Control Panel › Security › Certificate › Add › Add a new certificate: import the private key, certificate and intermediate, or get one from Let's Encrypt (the NAS name must resolve publicly and port 80 must reach it).",
            "Certificate › Settings: assign it to DSM (system default) and any other services (WebDAV, Hyper Backup Vault, Synology Drive, reverse proxy entries).",
            "Delete the factory 'synology' certificate once nothing uses it, then re-check here."].compactMap { $0 },
            commands: ["sudo ls /usr/syno/etc/certificate/_archive/   # read-only: one folder per imported certificate",
                       "sudo cat /usr/syno/etc/certificate/_archive/DEFAULT   # id of the default certificate"],
            docs: [KB.synology, KB.pki])
    }
    public static func pve(host: String, why: String? = nil) -> Guidance {
        Guidance(title: "Proxmox VE: custom certificate or ACME", steps: [why,
            "Custom: Node › System › Certificates › Upload Custom Certificate, or pvenode cert set on the node (full chain first, then the key).",
            "ACME: register an account, set the node's domain, then order; renewal is automatic.",
            "pveproxy restarts to load it. The cluster-CA files (pve-ssl.pem) stay in place for intra-cluster use."].compactMap { $0 },
            commands: ["pvenode cert info",
                       "pvenode cert set fullchain.pem key.pem --restart 1 --force 1",
                       "pvenode acme account register default admin@\(AppConfig.current.defaultDomain)",
                       "pvenode config set --acme domains=\(Shell.quote(host))",
                       "pvenode acme cert order"],
            docs: [KB.proxmox, KB.pki])
    }
    public static func pbs(why: String? = nil) -> Guidance {
        Guidance(title: "Proxmox Backup Server: certificate and fingerprint", steps: [why,
            "Default: PBS uses a self-signed certificate; clients pin its SHA-256 fingerprint (Dashboard › Show Fingerprint).",
            "Custom/ACME: Configuration › Certificates › Upload Custom Certificate, or ACME. With a CA-trusted certificate the PVE storage fingerprint can be removed.",
            "After regenerating or replacing the certificate, update the fingerprint on every PVE storage entry and client."].compactMap { $0 },
            commands: ["proxmox-backup-manager cert info",
                       "proxmox-backup-manager cert update --force   # regenerates the self-signed cert: the fingerprint changes",
                       "pvesm set STORAGE_ID --fingerprint 'AA:BB:…'",
                       "export PBS_FINGERPRINT='AA:BB:…'   # proxmox-backup-client"],
            docs: [KB.proxmox])
    }
    public static func binding(_ s: Service?, host: String, why: String?) -> Guidance? {
        switch s {
        case .synologyDSM: return dsm(why: why)
        case .proxmoxVE: return pve(host: host, why: why)
        case .proxmoxBackup: return pbs(why: why)
        default: return nil
        }
    }
    public static func guidance(for f: Finding, target: Target?) -> [Guidance] {
        let host = target?.verifyName ?? AppConfig.current.hostPlaceholder
        switch f.kind {
        case "dsm-cert": return [dsm()]
        case "pve-cert": return [pve(host: host)]
        case "pbs-cert", "pbs-pin": return f.severity >= .warning || f.kind == "pbs-cert" ? [pbs()] : []
        case "fingerprint": return target.flatMap { binding($0.service, host: host, why: nil) }.map { [$0] } ?? []
        default: return []
        }
    }
}

/// Form state of the app's Appliances pane, kept in Core so it can be unit tested.
public struct ApplianceForm: Equatable {
    public var host = "", service: Service = .synologyDSM, port = "5001", expected = "", fingerprint = ""
    public init() {}
    public mutating func select(_ s: Service) { service = s; port = String(s.defaultPort); if s != .proxmoxBackup { fingerprint = "" } }
    public var canRun: Bool { !host.trimmingCharacters(in: .whitespaces).isEmpty }
    public var target: Target {
        let h = host.trimmingCharacters(in: .whitespaces), fp = fingerprint.trimmingCharacters(in: .whitespaces)
        var t = Target(name: h, host: h, port: Int(port.trimmingCharacters(in: .whitespaces)) ?? -1, service: service,
                       expectedName: expected.trimmingCharacters(in: .whitespaces), platform: service.defaultPlatform ?? .generic)
        t.fingerprintPin = service == .proxmoxBackup && !fp.isEmpty ? fp : nil
        return t
    }
}
