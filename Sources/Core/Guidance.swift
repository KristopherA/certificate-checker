import Foundation

/// Fix guidance. Commands are display/copy-only; the app never executes them.
public struct Guidance: Identifiable, Equatable {
    public var id: String { title }
    public let title: String
    public let steps: [String]
    public let commands: [String]
    public let docs: [String]
}

public enum Advisor {
    public static func guidance(for topic: Topic, platform: Platform, target: Target? = nil) -> [Guidance] {
        // Remote-admin targets left on Generic get their Windows guidance.
        let platform = platform == .generic ? (target?.service.defaultPlatform ?? platform) : platform
        let host = target?.verifyName ?? "HOST"
        let qh = Shell.quote(host)
        var out: [Guidance] = []
        switch topic {
        case .expiry, .weakKey, .weakSignature, .eku, .noSAN, .hostname, .caLeaf, .longValidity:
            out.append(replace(platform, host: host, reason: topic, service: target?.service))
        case .chainOrder, .chainIncomplete:
            out.append(Guidance(title: "Serve the full chain in order", steps: [
                "Build the bundle as leaf first, then each intermediate. Do not include the root unless the platform requires it.",
                "Download the matching intermediate from the issuing CA (AD CS: certsrv or the CA's AIA path; pfSense: System › Cert Manager › CAs › Export).",
                "Re-import the bundle on the service, then re-check here."
            ], commands: ["cat leaf.crt intermediate.crt > fullchain.pem", "\(Shell.openssl) crl2pkcs7 -nocrl -certfile fullchain.pem | \(Shell.openssl) pkcs7 -print_certs -noout"], docs: [KB.pki, KB.runbook]))
            out.append(replace(platform, host: host, reason: topic, service: target?.service))
        case .trust:
            out.append(Guidance(title: "Establish trust in the issuing CA", steps: [
                "Identify the root CA in the chain. For AD CS or a pfSense internal CA, the root must be distributed to clients (GPO for Windows, configuration profile for macOS).",
                "Do not add trust for a leaf certificate. Distribute the CA through the normal managed process.",
                "If the server omitted an intermediate, fix the server chain instead (see chain guidance).",
            ], commands: ["security verify-cert -c leaf.pem -p ssl -s \(qh)", "\(Shell.openssl) verify -CAfile root.pem -untrusted intermediate.pem leaf.pem"], docs: [KB.pki, KB.checklist]))
            if platform == .proxmoxBackup { out.append(pbsFingerprint) }
        case .keyMismatch:
            out.append(Guidance(title: "Pair the certificate with its private key", steps: [
                "The certificate was issued for a different key. Locate the key generated with the CSR, or create a new CSR and reissue.",
                "Run the comparison on an approved admin workstation. Both hashes must be identical.",
                "Never email or ticket private keys."
            ], commands: ["\(Shell.openssl) x509 -in cert.pem -noout -pubkey | \(Shell.openssl) pkey -pubin -outform pem | \(Shell.openssl) sha256", "\(Shell.openssl) pkey -in key.pem -pubout -outform pem | \(Shell.openssl) sha256"], docs: [KB.runbook, KB.pki]))
        case .startTLS:
            out.append(Guidance(title: "Enable TLS on the service", steps: startTLSSteps(target?.service, platform), commands: target.map { [Probe.opensslCommand($0)] } ?? [], docs: startTLSDocs(target?.service)))
        case .connection:
            out.append(Guidance(title: "Check reachability first", steps: [
                "Confirm the host name resolves and the port is open from this network (VPN state matters for internal services).",
                "For HTTPS targets, use Connection Workbench to compare DNS, proxy and route evidence.",
                "Check the firewall rule on pfSense (Firewall › Rules) for the source network."
            ], commands: ["nc -vz \(Shell.quote(target?.host ?? "HOST")) \(target?.port ?? 443)", target.map(Probe.opensslCommand) ?? "\(Shell.openssl) s_client -connect HOST:443 </dev/null"], docs: [KB.pfSense]))
        case .csr, .general, .wireguard, .ipsec, .radius, .remote, .appliance, .stack: break
        }
        return out
    }

    static let pbsFingerprint = Guidance(title: "Proxmox Backup Server: keep the self-signed fingerprint pinned", steps: [
        "PBS uses its own self-signed certificate by default; PVE trusts it through the fingerprint stored with the storage entry, not the system trust store.",
        "Read the current fingerprint on the PBS host, then compare it to the PVE storage configuration (Datacenter › Storage › the PBS entry).",
        "If PBS regenerated its certificate, update the fingerprint in PVE."
    ], commands: ["proxmox-backup-manager cert info | grep -i fingerprint", "grep -A8 'pbs:' /etc/pve/storage.cfg", "pvesm set STORAGE_ID --fingerprint 'AA:BB:…'"], docs: [KB.proxmox])

    static func startTLSSteps(_ s: Service?, _ p: Platform) -> [String] {
        switch s {
        case .ldapStartTLS: return ["StartTLS on 389 needs a valid Server Authentication certificate in the DC's Local Computer › Personal store, the same one LDAPS on 636 uses.", "Confirm the certificate includes the DC FQDN and the domain name in the SAN.", "After installing, the DC picks it up without reboot; force with the renewServerCertificate LDIF in the KB."]
        case .mysql: return ["Set ssl_ca, ssl_cert and ssl_key in my.cnf (MySQL 8 enables TLS automatically when files are present).", "Reload with ALTER INSTANCE RELOAD TLS (MySQL 8.0.16+) or restart the service.", "Confirm with SHOW VARIABLES LIKE 'have_ssl'."]
        case .smtpStartTLS, .imapStartTLS, .pop3StartTLS: return p == .zimbra ? ["Check zimbraMtaTlsSecurityLevel and that a commercial or self-signed certificate is deployed with zmcertmgr.", "Restart the MTA/mailbox services after deploying."] : ["Enable STARTTLS on the mail service and configure the certificate and key paths.", "Some ports (465, 993, 995) use implicit TLS instead; choose the matching service type."]
        case .rdp: return ["The RDP server refused TLS or chose Standard RDP Security. Set the Security Layer to SSL (TLS) or Negotiate and require NLA (Group Policy › Remote Desktop Session Host › Security).", "SSL_CERT_NOT_ON_SERVER means the bound certificate is missing or NETWORK SERVICE cannot read its private key: re-bind it (RDP certificate guidance).", "A reply that is not TPKT means the port is not RDP: check the port and any RDP-aware proxy in front of it."]
        default: return ["The server accepted the connection but did not negotiate TLS. Confirm the port and service type."]
        }
    }
    static func startTLSDocs(_ s: Service?) -> [String] {
        switch s { case .rdp: return [KB.rdp]; case .ldapStartTLS: return [KB.ldapsReplace, KB.ldapRef]; case .mysql: return [KB.mysqlRotation, KB.mysqlAdmin]; default: return [KB.zimbra, KB.pki] }
    }

    static func replace(_ p: Platform, host: String, reason: Topic, service: Service? = nil) -> Guidance {
        let why: String = {
            switch reason {
            case .expiry: return "Renew before expiry."
            case .hostname, .noSAN: return "Reissue with every service name (\(host)) in the SAN."
            case .eku: return "Reissue from a template/profile with Server Authentication EKU."
            case .weakKey: return "Reissue with RSA 2048+ or ECDSA P-256."
            case .weakSignature: return "Reissue signed with SHA-256 or stronger."
            default: return "Reissue or replace the certificate."
            }
        }()
        let qh = Shell.quote(host), base = Shell.quote(host + ".key"), csrName = Shell.quote(host + ".csr")
        // Key is written with umask 077 (mode 600); remove it from the working folder once it is installed on the server.
        let csr = "(umask 077 && \(Shell.serverOpenSSL) req -new -newkey rsa:2048 -nodes -keyout \(base) -out \(csrName) -subj \(Shell.quote("/CN=" + host)) -addext \(Shell.quote("subjectAltName=DNS:" + host))) && chmod 600 \(base)  # delete the .key after installing it: rm -P \(base)"
        _ = qh
        switch p {
        case .pfSense:
            return Guidance(title: "pfSense: replace via Cert Manager", steps: [why, "System › Cert Manager › Certificates: renew (internal CA) or import the new certificate and key.", "Assign it where used: System › Advanced › Admin Access (GUI), VPN › IPsec › Phase 1 (IKEv2 'My Certificate'), or the service using it.", "For IPsec, also confirm clients trust the issuing CA and that the SAN matches the IKE identifier."], commands: ["/etc/rc.restart_webgui", "swanctl --list-certs"], docs: [KB.pfSense, KB.pki])
        case .windowsAD:
            return Guidance(title: "Active Directory: replace the LDAPS certificate", steps: [why, "Request a new certificate from the AD CS 'Domain Controller Authentication' or Kerberos template on the DC (certlm.msc › Personal › Request New Certificate).", "Remove the expired certificate after the new one is in place.", "Force LDAPS to load the new certificate without reboot using the LDIF below, then re-check LDAPS 636 and StartTLS 389."], commands: ["certutil -store My", "certutil -verify -urlfetch new-dc.cer", "Set-Content renew.ldf \"dn:`nchangetype: modify`nadd: renewServerCertificate`nrenewServerCertificate: 1`n-\"", "ldifde -i -f renew.ldf"], docs: [KB.ldapsReplace, KB.ldapRef, KB.pki])
        case .synology where service == .synologyDSM, .proxmoxVE where service == .proxmoxVE, .proxmoxBackup where service == .proxmoxBackup:
            return ApplianceAdvisor.binding(service, host: host, why: why) ?? Guidance(title: "Reissue and redeploy", steps: [why], commands: [], docs: [KB.pki])
        case .dockerRegistry where service == .dockerRegistry, .elasticStack where service == .logstashBeats || service == .elasticsearch:
            return StackAdvisor.binding(service, host: host, port: nil, why: why) ?? Guidance(title: "Reissue and redeploy", steps: [why], commands: [], docs: [KB.pki])
        case .dockerRegistry:
            return StackAdvisor.registry(host: host, port: 443, why: why)
        case .elasticStack:
            return StackAdvisor.filebeat(why: why)
        case .windowsIIS where service?.isRemoteAdmin == true:
            return RemoteAdvisor.binding(service, host: host, why: why) ?? Guidance(title: "Reissue and redeploy", steps: [why, "Import the new certificate into Local Computer › Personal and bind it to the service."], commands: [], docs: [KB.pki])
        case .windowsIIS:
            return Guidance(title: "Windows IIS / RD Gateway: bind the new certificate", steps: [why, "Import the PFX into Local Computer › Personal.", "IIS Manager › Site › Bindings › https › select the new certificate. For RD Gateway: RD Gateway Manager › Properties › SSL Certificate."], commands: ["Get-ChildItem Cert:\\LocalMachine\\My | Select Subject, NotAfter, Thumbprint", "netsh http show sslcert"], docs: [KB.pki])
        case .nginx:
            return Guidance(title: "nginx: deploy the new certificate", steps: [why, "ssl_certificate must point to the full chain (leaf first); ssl_certificate_key to the matching key.", "Test the configuration before reloading."], commands: [csr, "nginx -t && systemctl reload nginx"], docs: [KB.reverseProxy, KB.pki])
        case .apache:
            return Guidance(title: "Apache: deploy the new certificate", steps: [why, "SSLCertificateFile should reference the full chain (Apache 2.4.8+); SSLCertificateKeyFile the matching key."], commands: [csr, "apachectl configtest && systemctl reload apache2"], docs: [KB.reverseProxy, KB.pki])
        case .zimbra:
            return Guidance(title: "Zimbra: verify and deploy with zmcertmgr", steps: [why, "Place the key in /opt/zimbra/ssl/zimbra/commercial/commercial.key, then verify and deploy the certificate with its chain as the zimbra user.", "Restart Zimbra services in a maintenance window."], commands: ["su - zimbra -c '/opt/zimbra/bin/zmcertmgr verifycrt comm /opt/zimbra/ssl/zimbra/commercial/commercial.key /tmp/cert.crt /tmp/ca_chain.crt'", "su - zimbra -c '/opt/zimbra/bin/zmcertmgr deploycrt comm /tmp/cert.crt /tmp/ca_chain.crt'", "su - zimbra -c 'zmcontrol restart'"], docs: [KB.zimbra, KB.pki])
        case .mysql:
            return Guidance(title: "MySQL: rotate the server certificate", steps: [why, "Replace the files referenced by ssl_cert, ssl_key and ssl_ca, keeping ownership mysql:mysql and key mode 600.", "Reload TLS online (MySQL 8.0.16+), then confirm the new expiry."], commands: ["mysql -e \"ALTER INSTANCE RELOAD TLS;\"", "mysql -e \"SHOW STATUS LIKE 'Ssl_server_not_after';\""], docs: [KB.mysqlRotation, KB.mysqlAdmin])
        case .synology:
            return Guidance(title: "Synology DSM: replace the certificate", steps: [why, "Control Panel › Security › Certificate › Add › Replace an existing certificate (import key, certificate and intermediate).", "Use Settings to assign the certificate to each service (DSM, WebDAV, Hyper Backup Vault…)."], commands: [], docs: [KB.synology, KB.pki])
        case .proxmoxVE:
            return Guidance(title: "Proxmox VE: install a custom certificate", steps: [why, "Upload in the GUI (Node › System › Certificates) or use pvenode on the node.", "pveproxy restarts to load it; verify afterwards."], commands: ["pvenode cert set fullchain.pem key.pem --restart 1 --force 1", "pvenode cert info"], docs: [KB.proxmox])
        case .proxmoxBackup:
            return Guidance(title: "Proxmox Backup Server: regenerate the self-signed certificate", steps: [why, "Regenerating changes the fingerprint; update the fingerprint on every PVE storage entry afterwards."], commands: ["proxmox-backup-manager cert update --force", "proxmox-backup-manager cert info | grep -i fingerprint", "pvesm set STORAGE_ID --fingerprint 'AA:BB:…'"], docs: [KB.proxmox])
        case .windowsRDP:
            return RemoteAdvisor.rdpBinding(why: why)
        case .windowsRDGateway:
            return RemoteAdvisor.rdgBinding(why: why)
        case .windowsWinRM:
            return RemoteAdvisor.winrmListener(host: host, why: why)
        case .macOS:
            return Guidance(title: "macOS: inspect the identity", steps: [why, "Use Keychain Access to check the certificate and its private key are both present in the same keychain."], commands: ["security find-identity -v", "security find-certificate -a -c \(Shell.quote(host)) -p"], docs: [KB.pki])
        case .generic:
            return Guidance(title: "Reissue and redeploy", steps: [why, "Generate a CSR on the server (or the platform's own wizard), submit to the CA, deploy the full chain, and re-check here."], commands: [csr], docs: [KB.pki, KB.runbook])
        }
    }
}

/// Connection Workbench hand-off: HTTPS targets only, because Workbench tests HTTP(S) URLs.
public enum WorkbenchHandoff {
    public static let bundleID = "tools.connectionworkbench.desktop"
    public static var appURL: URL? { AppConfig.current.connectionWorkbenchApp.map { URL(fileURLWithPath: AppConfig.expand($0)) } }
    public static func url(for t: Target) -> String? {
        guard t.service == .https || t.service == .rdGateway else { return nil }
        let h = t.host.contains(":") ? "[\(t.host)]" : t.host
        return t.port == 443 ? "https://\(h)" : "https://\(h):\(t.port)"
    }
}
