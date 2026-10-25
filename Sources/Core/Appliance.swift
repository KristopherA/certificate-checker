import Foundation

// MARK: Synology DSM (5001), Proxmox VE (8006), Proxmox Backup Server (8007). TLS handshake only: no HTTP request, no login.

/// SHA-256 certificate fingerprint pins in the colon-hex form PBS/PVE clients use (AA:BB:…, 32 bytes).
public enum FingerprintPin {
    /// Normalises a user-supplied pin to upper-case colon-hex. Accepts colon-separated or plain hex (64 digits); nil otherwise.
    public static func normalize(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.count <= 200 else { return nil }
        let parts = t.contains(":") ? t.split(separator: ":", omittingEmptySubsequences: false).map(String.init) : stride(from: 0, to: t.count, by: 2).map { i -> String in
            let a = t.index(t.startIndex, offsetBy: i), b = t.index(a, offsetBy: min(2, t.count - i)); return String(t[a..<b]) }
        guard parts.count == 32, parts.allSatisfy({ $0.count == 2 && $0.allSatisfy(isASCIIHex) }) else { return nil }
        return parts.map { $0.uppercased() }.joined(separator: ":")
    }
    /// ASCII 0-9 a-f A-F only. Character.isHexDigit also accepts fullwidth forms (e.g. U+FF10), which would then
    /// report a confusing mismatch instead of a malformed pin.
    static func isASCIIHex(_ c: Character) -> Bool {
        guard c.unicodeScalars.count == 1, let v = c.unicodeScalars.first?.value else { return false }
        return (0x30...0x39).contains(v) || (0x41...0x46).contains(v) || (0x61...0x66).contains(v)
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

    public static func adjust(_ findings: [Finding], chain: [Certificate], target: Target, now: Date = Clock.now()) -> [Finding] {
        guard let leaf = chain.first, target.service.isAppliance else { return findings }
        var out = findings
        func downgradeTrust(_ note: String, to sev: Severity = .warning, pinned: Bool = false) {
            // Only when the trust failure is explained by the default CA/self-signed setup: inside validity, signatures
            // verify, and the top is a verified self-signed root unless the leaf matched the user's fingerprint pin.
            guard let i = out.firstIndex(where: { $0.id == "trust" }), out[i].severity == .fail,
                  leaf.notBefore <= now, now <= leaf.notAfter, ChainCheck.verify(chain, now: now, trustedTop: pinned).ok else { return }
            out[i].severity = sev; out[i].detail += " " + note
        }
        /// Pin comparison shared by PBS and PVE. `leaf.sha256` is upper-case colon-hex (locked by ApplianceTests), the same
        /// form FingerprintPin.normalize returns, so a plain string comparison is exact.
        func pinFindings(_ p: String, raw: String, explainedTrust: Bool, hint: String) {
            let id = "\(p)-pin"
            guard let pin = FingerprintPin.normalize(raw) else {
                out.append(Finding(id, .fail, .appliance, "Fingerprint pin is not a SHA-256 colon-hex value", "Expected 32 bytes as AA:BB:… (64 ASCII hex digits). Copy it from \(hint)", kind: id)); return
            }
            if pin == leaf.sha256 {
                // Leaf only (not self-issued): there is no chain to verify, so trust rests on the pin alone. Say "pinned".
                let leafOnly = chain.count == 1 && !leaf.isSelfIssued
                out.append(Finding(id, .pass, .appliance, "Fingerprint pin matches the served certificate", pin + (leafOnly ? " · Pinned: the server sent only its own certificate, so no issuing chain was checked." : ""), kind: id))
                if explainedTrust { downgradeTrust(leafOnly ? "Pinned: matches the fingerprint pin; the server sent only its own certificate, so the issuing chain was not checked." : "Trusted by the matching fingerprint pin.", to: .info, pinned: true) }
            } else {
                out.append(Finding(id, .fail, .appliance, "Fingerprint pin does NOT match the served certificate", "Pinned \(pin), served \(leaf.sha256). The certificate was regenerated or replaced, or something else answers on \(target.endpoint). Confirm on the host before updating the pin.", kind: id))
            }
        }
        let product = target.service.rawValue.replacingOccurrences(of: " (HTTPS)", with: "")
        out.append(Finding("appl-fp", .info, .appliance, "Presented certificate SHA-256 fingerprint \(leaf.sha256)", "\(product) on \(target.endpoint). Shown for comparison only.", kind: "fingerprint"))
        switch target.service {
        case .synologyDSM:
            if isSynologyDefault(leaf) {
                out.append(Finding("dsm-default", .warning, .appliance, "Synology DSM factory certificate", "\(leaf.displayName), issued by \(leaf.issuer.commonName ?? leaf.issuer.text). Browsers and Hyper Backup / Drive clients warn. Replace it with a CA-issued or Let's Encrypt certificate and assign it to DSM. Identity is unverified: nothing ties this certificate to your NAS, so compare the SHA-256 fingerprint shown here with Control Panel › Security › Certificate on the NAS.", kind: "dsm-cert"))
                downgradeTrust("Expected for the DSM factory certificate.")
            } else if leaf.isSelfIssued {
                out.append(Finding("dsm-selfsigned", .warning, .appliance, "Synology DSM presents a self-signed certificate", "Clients cannot verify it. Assign a CA-issued certificate to DSM.", kind: "dsm-cert"))
            }
        case .proxmoxVE:
            // One trimmed-empty test for both the downgrade and the pin check: a whitespace-only pin counts as no pin.
            let pveRaw = target.fingerprintPin.flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0 }
            if isPVEDefault(leaf) {
                out.append(Finding("pve-default", .warning, .appliance, "Proxmox VE default node certificate (cluster CA)", "Issued by \(leaf.issuer.commonName ?? leaf.issuer.text), the cluster's own CA, which browsers do not trust. Install a custom certificate or use the built-in ACME client; pveproxy then serves it from pveproxy-ssl.pem.\(pveRaw == nil ? " Identity is unverified without a fingerprint pin: supply --fingerprint (pvenode cert info) to confirm this is your node." : "")", kind: "pve-cert"))
                if pveRaw == nil { downgradeTrust("Expected for the default PVE cluster-CA certificate; identity unverified without a fingerprint pin.") }
            } else if leaf.isSelfIssued {
                out.append(Finding("pve-selfsigned", .warning, .appliance, "Proxmox VE presents a self-signed certificate", "Clients cannot verify it. Install a CA-issued certificate or use ACME.", kind: "pve-cert"))
            }
            if let raw = pveRaw {
                pinFindings("pve", raw: raw, explainedTrust: isPVEDefault(leaf) || leaf.isSelfIssued, hint: "pvenode cert info on the node (or the GUI: Node › System › Certificates).")
            }
        case .proxmoxBackup:
            let selfSigned = isPBSDefault(leaf)
            if selfSigned { out.append(Finding("pbs-selfsigned", .info, .appliance, "Proxmox Backup Server self-signed certificate (default)", "PVE and proxmox-backup-client trust it only through a pinned SHA-256 fingerprint.", kind: "pbs-cert")) }
            if let raw = target.fingerprintPin, !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                pinFindings("pbs", raw: raw, explainedTrust: selfSigned, hint: "proxmox-backup-manager cert info or the PBS dashboard › Show Fingerprint.")
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
        case "pve-pin": return f.severity >= .warning ? [pve(host: host)] : []
        case "fingerprint": return target.flatMap { binding($0.service, host: host, why: nil) }.map { [$0] } ?? []
        default: return []
        }
    }
}

/// Form state of the app's Appliances pane, kept in Core so it can be unit tested.
public struct ApplianceForm: Equatable {
    public var host = "", service: Service = .synologyDSM, port = "5001", expected = "", fingerprint = ""
    public init() {}
    public mutating func select(_ s: Service) { service = s; port = String(s.defaultPort); if !s.acceptsFingerprintPin { fingerprint = "" } }
    public var canRun: Bool { !host.trimmingCharacters(in: .whitespaces).isEmpty }
    public var target: Target {
        let h = host.trimmingCharacters(in: .whitespaces), fp = fingerprint.trimmingCharacters(in: .whitespaces)
        var t = Target(name: h, host: h, port: Int(port.trimmingCharacters(in: .whitespaces)) ?? -1, service: service,
                       expectedName: expected.trimmingCharacters(in: .whitespaces), platform: service.defaultPlatform ?? .generic)
        t.fingerprintPin = service.acceptsFingerprintPin && !fp.isEmpty ? fp : nil
        return t
    }
}
