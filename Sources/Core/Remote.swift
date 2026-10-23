import Foundation

// MARK: RDP negotiation (MS-RDPBCGR 2.2.1.1 / 2.2.1.2). Pure functions so they can be unit tested.

public enum RDP {
    public static let protocolRDP: UInt32 = 0, protocolSSL: UInt32 = 0x1, protocolHybrid: UInt32 = 0x2
    public static let protocolRDSTLS: UInt32 = 0x4, protocolHybridEx: UInt32 = 0x8, protocolRDSAAD: UInt32 = 0x10
    /// Remote Desktop Authentication EKU, accepted by RDP in place of Server Authentication.
    public static let remoteDesktopAuthEKU = "1.3.6.1.4.1.311.54.1.2"

    public enum Negotiation: Equatable {
        case selected(UInt32, flags: UInt8)
        case failure(UInt32)
        /// Connection Confirm without RDP_NEG_RSP: the server only speaks Standard RDP Security.
        case legacy
    }

    static func le32(_ v: UInt32) -> [UInt8] { withUnsafeBytes(of: v.littleEndian) { Array($0) } }

    /// TPKT + X.224 Connection Request + RDP_NEG_REQ. No routing token, no cookie (no user name is sent).
    public static func connectionRequest(requested: UInt32 = protocolSSL | protocolHybrid) -> [UInt8] {
        let neg: [UInt8] = [0x01, 0x00, 0x08, 0x00] + le32(requested)
        let x224: [UInt8] = [UInt8(6 + neg.count), 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00] + neg
        let total = 4 + x224.count
        return [0x03, 0x00, UInt8(total >> 8), UInt8(total & 0xFF)] + x224
    }

    /// Validates a TPKT header and returns the length of the TPDU that follows.
    public static func tpktLength(_ head: [UInt8]) throws -> Int {
        guard head.count == 4, head[0] == 0x03, head[1] == 0x00 else { throw CheckError.message("Not an RDP server: the reply is not a TPKT (RFC 1006) packet.") }
        let len = Int(head[2]) << 8 | Int(head[3])
        guard (11...1024).contains(len) else { throw CheckError.message("Not an RDP server: TPKT length \(len) is out of range.") }
        return len - 4
    }

    /// Parses the X.224 TPDU (after the TPKT header).
    public static func parseConfirm(_ t: [UInt8]) throws -> Negotiation {
        guard t.count >= 7, Int(t[0]) + 1 <= t.count else { throw CheckError.message("Truncated X.224 reply.") }
        switch t[1] & 0xF0 {
        case 0xD0: break
        case 0x80: throw CheckError.message("The server sent an X.224 Disconnect Request instead of a Connection Confirm.")
        default: throw CheckError.message(String(format: "Unexpected X.224 TPDU code 0x%02X.", t[1]))
        }
        guard t[0] >= 14, t.count >= 15 else { return .legacy }
        let n = Array(t[7..<15])
        guard n[2] == 0x08, n[3] == 0x00 else { throw CheckError.message("Malformed RDP negotiation response (length field).") }
        let value = UInt32(n[4]) | UInt32(n[5]) << 8 | UInt32(n[6]) << 16 | UInt32(n[7]) << 24
        switch n[0] {
        case 0x02: return .selected(value, flags: n[1])
        case 0x03: return .failure(value)
        default: throw CheckError.message(String(format: "Unknown RDP negotiation type 0x%02X.", n[0]))
        }
    }

    public static func protocolName(_ p: UInt32) -> String {
        switch p {
        case protocolRDP: return "Standard RDP Security (PROTOCOL_RDP, no TLS)"
        case protocolSSL: return "TLS without NLA (PROTOCOL_SSL)"
        case protocolHybrid: return "CredSSP / NLA (PROTOCOL_HYBRID)"
        case protocolRDSTLS: return "RDSTLS"
        case protocolHybridEx: return "CredSSP with Early User Authorization (PROTOCOL_HYBRID_EX)"
        case protocolRDSAAD: return "RDS AAD Auth"
        default: return String(format: "unknown protocol 0x%08X", p)
        }
    }
    public static func failureName(_ c: UInt32) -> (name: String, meaning: String) {
        switch c {
        case 1: return ("SSL_REQUIRED_BY_SERVER", "The server requires TLS but the request did not offer it.")
        case 2: return ("SSL_NOT_ALLOWED_BY_SERVER", "The server allows only Standard RDP Security (Security Layer = RDP). TLS is disabled.")
        case 3: return ("SSL_CERT_NOT_ON_SERVER", "The server has no usable certificate: the bound certificate is missing, or NETWORK SERVICE cannot read its private key.")
        case 4: return ("INCONSISTENT_FLAGS", "The server rejected the requested protocol flags.")
        case 5: return ("HYBRID_REQUIRED_BY_SERVER", "The server requires CredSSP / NLA.")
        case 6: return ("SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER", "The server requires TLS with client certificate authentication.")
        default: return ("failure code \(c)", "Unknown negotiation failure.")
        }
    }
    /// True when the selected protocol starts with a TLS handshake that this probe can complete.
    public static func startsTLS(_ n: Negotiation) -> Bool {
        // Only the protocols this probe requested (SSL | HYBRID). HYBRID_EX, RDSTLS and RDS AAD were not offered.
        if case .selected(let p, _) = n { return p == protocolSSL || p == protocolHybrid }
        return false
    }
    public static func describe(_ n: Negotiation) -> String {
        switch n {
        case .selected(let p, _): return "RDP negotiation: server selected \(protocolName(p))"
        case .failure(let c): return "RDP negotiation failed: \(failureName(c).name)"
        case .legacy: return "RDP server did not negotiate (no RDP_NEG_RSP): Standard RDP Security only"
        }
    }
    public static func findings(_ n: Negotiation) -> [Finding] {
        switch n {
        case .selected(let p, _) where p == protocolHybrid:
            return [Finding("rdp-neg", .pass, .remote, "RDP: server selected \(protocolName(p))", "Network Level Authentication is required. This probe stops after the TLS handshake and sends no credentials.", kind: "rdp-neg")]
        case .selected(let p, _) where p == protocolSSL:
            return [Finding("rdp-nla", .warning, .remote, "RDP: TLS without Network Level Authentication", "CredSSP was offered but the server chose plain TLS, so the logon screen is reachable before authentication. Require NLA on the host.", kind: "rdp-nla")]
        case .selected(let p, _) where p == protocolRDP:
            return [Finding("rdp-neg", .fail, .remote, "RDP: server selected Standard RDP Security (no TLS)", "The server ignored the TLS/CredSSP request. Set the Security Layer to SSL (TLS) or Negotiate and require NLA.", kind: "rdp-security")]
        case .selected(let p, _):
            return [Finding("rdp-neg", .fail, .remote, "RDP: server selected a protocol that was not requested", "\(protocolName(p)). Only PROTOCOL_SSL | PROTOCOL_HYBRID was offered, so the server is not following MS-RDPBCGR negotiation (or something in between rewrote it).", kind: "rdp-security")]
        case .failure(let c):
            let f = failureName(c)
            return [Finding("rdp-neg", .fail, .remote, "RDP negotiation failed: \(f.name)", f.meaning, kind: c == 3 ? "rdp-cert" : "rdp-security")]
        case .legacy:
            return [Finding("rdp-neg", .fail, .remote, "RDP server did not negotiate TLS", "The Connection Confirm carried no RDP negotiation response: the server speaks only Standard RDP Security (very old, or Security Layer = RDP).", kind: "rdp-security")]
        }
    }
}

// MARK: Certificate rules specific to RDP, RD Gateway and WinRM

public enum Remote {
    /// Likely the self-signed certificate Windows generates for RDP (Remote Desktop store): self-issued, not a CA.
    public static func isDefaultSelfSigned(_ leaf: Certificate) -> Bool { leaf.isSelfIssued && leaf.isCA != true }

    public static func adjust(_ findings: [Finding], chain: [Certificate], target: Target, now: Date = Clock.now()) -> [Finding] {
        guard let leaf = chain.first, target.service.isRemoteAdmin else { return findings }
        var out = findings
        func set(_ f: Finding) { if let i = out.firstIndex(where: { $0.id == f.id }) { out[i] = f } else { out.append(f) } }
        let thumb = leaf.sha1.replacingOccurrences(of: ":", with: "")
        out.append(Finding("remote-thumb", .info, .remote, "Presented certificate thumbprint (SHA-1) \(thumb)", "Compare with the thumbprint bound on the server (see How to fix). It is shown for comparison only.", kind: "thumb"))
        switch target.service {
        case .rdp:
            if let eku = leaf.extendedKeyUsage {
                let names = eku.map(OID.name).joined(separator: ", ")
                let server = eku.contains(OID.serverAuth) || eku.contains(OID.anyEKU), rda = eku.contains(RDP.remoteDesktopAuthEKU)
                if server || rda {
                    set(Finding("eku", .pass, .eku, "Extended key usage allows RDP", "Present: \(names). RDP accepts Server Authentication or Remote Desktop Authentication (\(RDP.remoteDesktopAuthEKU))."))
                } else {
                    set(Finding("eku", .fail, .eku, "Extended key usage does not allow RDP", "Present: \(names). Reissue with Server Authentication (\(OID.serverAuth)) or Remote Desktop Authentication (\(RDP.remoteDesktopAuthEKU))."))
                }
                if rda && !server {
                    // Apple's TLS server policy requires serverAuth; evaluate the chain with the X.509 policy instead.
                    let t = Trust.evaluate(chain, hostname: nil, purpose: .any, allowNetwork: true)
                    set(Finding("trust", t.trusted ? .pass : .fail, .trust, t.trusted ? "Chain trusted by macOS (X.509 policy)" : "Not trusted by macOS (X.509 policy)",
                                t.message + ". The certificate carries only the Remote Desktop Authentication EKU, so the TLS server policy was not applied; hostname coverage is checked separately."))
                }
            }
            if isDefaultSelfSigned(leaf) {
                let days = Int(leaf.notAfter.timeIntervalSince(leaf.notBefore) / 86_400)
                out.append(Finding("rdp-selfsigned", .warning, .remote, "Self-signed RDP certificate (likely the Windows default)",
                                   "\(leaf.displayName), issued by itself, \(days)-day lifetime. Clients show a certificate warning or trust it on first use. Bind a certificate from your CA.", kind: "rdp-cert"))
                // Downgrade only when the sole problem is an untrusted self-signed root: one certificate, inside its
                // validity dates, whose signature verifies with itself as the anchor.
                if let i = out.firstIndex(where: { $0.id == "trust" }), out[i].severity == .fail, chain.count == 1,
                   leaf.notBefore <= now, now <= leaf.notAfter, ChainCheck.verify([leaf], now: now).ok {
                    out[i].severity = .warning; out[i].detail += " Expected for a self-signed RDP certificate."
                }
                if leaf.signatureIsWeak { out.append(Finding("rdp-selfsigned-sig", .info, .weakSignature, "Self-signed certificate uses \(leaf.signatureAlgorithm)", "Regenerating or replacing it with a CA-issued SHA-256 certificate avoids client warnings.")) }
            }
        case .rdGateway:
            if leaf.isSelfIssued {
                out.append(Finding("rdg-selfsigned", .fail, .remote, "RD Gateway presents a self-signed certificate", "Remote Desktop clients refuse a gateway certificate they do not trust. Bind a certificate from a CA the clients trust, with the gateway's public name in the SAN.", kind: "rdg-cert"))
            }
        case .winrmHTTPS:
            let cn = leaf.subject.commonName ?? ""
            if !cn.isEmpty, cn.lowercased() != target.verifyName.lowercased(), !cn.hasPrefix("*") {
                out.append(Finding("winrm-cn", .warning, .remote, "Certificate CN \(cn) differs from \(target.verifyName)", "WinRM HTTPS listeners expect the certificate CN to equal the listener HostName, and clients connect with that name. Use a certificate whose CN (and SAN) is the host name clients use.", kind: "winrm-cert"))
            }
            if leaf.isSelfIssued {
                out.append(Finding("winrm-selfsigned", .warning, .remote, "WinRM presents a self-signed certificate", "Clients then need -SkipCACheck/-SkipCNCheck, which removes server authentication. Use a CA-issued certificate instead.", kind: "winrm-cert"))
            }
        default: break
        }
        return out.sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity }
    }
}

// MARK: WinRM HTTP (5985) listener check: only when explicitly requested. One unauthenticated POST, no credentials.

public struct RemoteHTTPResult { public var findings: [Finding] = []; public var transcript: [String] = [] }

public enum WinRMHTTP {
    public static let defaultPort = 5985
    public static func request(host: String, port: Int) -> String {
        let h = host.contains(":") ? "[\(host)]" : host
        return "POST /wsman HTTP/1.1\r\nHost: \(h):\(port)\r\nUser-Agent: certificate-checker\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    }
    public struct Response: Equatable { public let status: Int; public let schemes: [String]; public let server: String? }
    public static func parse(_ lines: [String]) -> Response? {
        guard let first = lines.first, first.hasPrefix("HTTP/1."), let code = Int(first.split(separator: " ").dropFirst().first ?? "") else { return nil }
        var schemes: [String] = [], server: String?
        for l in lines.dropFirst() {
            guard let c = l.firstIndex(of: ":") else { continue }
            let k = l[..<c].lowercased(), v = l[l.index(after: c)...].trimmingCharacters(in: .whitespaces)
            if k == "www-authenticate", let s = v.split(separator: " ").first { schemes.append(String(s)) }
            if k == "server" { server = Wire.sanitize(v) }
        }
        return Response(status: code, schemes: schemes, server: server)
    }
    public static func findings(_ r: Response?, port: Int, error: String? = nil) -> [Finding] {
        if let error { return [Finding("winrm-http", .info, .remote, "No WinRM HTTP listener answered on \(port)", "Connection failed (\(error)): closed or filtered. Nothing to disable.", kind: "winrm-http")] }
        guard let r else { return [Finding("winrm-http", .info, .remote, "Port \(port) answered, but not with HTTP", "", kind: "winrm-http")] }
        // "Microsoft-HTTPAPI" is the HTTP.sys kernel driver's Server header: any HTTP.sys service sends it, not only WinRM.
        let httpAPI = r.server?.localizedCaseInsensitiveContains("Microsoft-HTTPAPI") == true
        if (r.status == 401 && r.schemes.isEmpty) || (httpAPI && !(r.status == 401 && !r.schemes.isEmpty)) {
            return [Finding("winrm-http", .warning, .remote, "Likely a WinRM HTTP listener on \(port) (plaintext transport)", "\(httpAPI ? "Windows HTTP server (HTTP.sys) answered; other HTTP.sys services send the same header. " : "")Status \(r.status)\(r.schemes.isEmpty ? ", no WWW-Authenticate header" : "")\(r.server.map { ", Server: \($0)" } ?? ""). The HTTP transport is unencrypted; confirm with winrm enumerate winrm/config/listener on the host and prefer HTTPS on 5986.", kind: "winrm-http")]
        }
        let looksWinRM = r.status == 401 && !r.schemes.isEmpty
        guard looksWinRM else { return [Finding("winrm-http", .info, .remote, "HTTP on \(port) is not a WinRM listener (status \(r.status))", r.server.map { "Server: \($0)" } ?? "", kind: "winrm-http")] }
        let offered = r.schemes.joined(separator: ", ")
        if r.schemes.contains(where: { $0.caseInsensitiveCompare("Basic") == .orderedSame }) {
            return [Finding("winrm-http", .fail, .remote, "WinRM HTTP listener on \(port) offers Basic authentication over plaintext", "Offered: \(offered). Basic over HTTP exposes credentials. Disable Basic, keep AllowUnencrypted false, and use the HTTPS listener on 5986.", kind: "winrm-http")]
        }
        return [Finding("winrm-http", .warning, .remote, "WinRM HTTP listener is open on \(port) (plaintext transport)", "Offered: \(offered). The HTTP transport is unencrypted. With Kerberos/Negotiate and AllowUnencrypted=false WinRM still encrypts the message body, but prefer HTTPS on 5986 and limit 5985 to admin networks or remove it.", kind: "winrm-http")]
    }
    /// Synchronous; call from a dedicated thread (uses the current run loop).
    /// `host` is the name sent as the HTTP Host header; `connect` (a connect-IP override) is where the socket goes.
    public static func checkSync(host: String, connect: String? = nil, port: Int = defaultPort, timeout: TimeInterval = 10) -> RemoteHTTPResult {
        var out = RemoteHTTPResult()
        let connect = connect.flatMap { $0.isEmpty ? nil : $0 }
        guard Target.validHost(host), connect.map(Resolution.isIP) ?? true, (1...65535).contains(port) else { out.findings = [Finding("winrm-http", .fail, .connection, "Invalid host or port")]; return out }
        let source: ResolverSource = connect != nil ? .override : (Resolution.isIP(host) ? .literal : .system)
        do {
            let c = try StreamConnection(host: connect ?? host, port: port, timeout: timeout)
            defer { c.close() }
            try c.open()
            out.transcript.append(Resolution.connectedLine(host: host, ip: c.peerAddress(), port: port, source: source, requested: connect) + ": plaintext HTTP, explicitly requested")
            try c.write(request(host: host, port: port)); out.transcript.append("C: POST /wsman (no credentials, empty body)")
            var lines: [String] = []
            while lines.count < 60 {
                guard let l = try? c.readLine() else { break }
                if l.isEmpty { break }
                lines.append(l)
            }
            out.transcript += lines.prefix(12).map { "S: " + Wire.sanitize($0) }
            out.findings = findings(parse(lines), port: port)
        } catch {
            out.findings = findings(nil, port: port, error: error.localizedDescription)
        }
        return out
    }
    public static func check(host: String, connect: String? = nil, port: Int = defaultPort, timeout: TimeInterval = 10) async -> RemoteHTTPResult {
        await withCheckedContinuation { c in
            let t = Thread { c.resume(returning: checkSync(host: host, connect: connect, port: port, timeout: timeout)) }
            t.stackSize = 1 << 20; t.start()
        }
    }
}

// MARK: Copy-only guidance

public enum RemoteAdvisor {
    static let thumb = "'THUMBPRINT'"   // 40 hex characters, no spaces: replace before running
    static let tsSetting = "Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter \"TerminalName='RDP-tcp'\""

    public static func rdpBinding(why: String? = nil) -> Guidance {
        Guidance(title: "RDP host: bind a CA-issued certificate", steps: [why, "Import the certificate with its private key into Local Computer › Personal (certlm.msc). EKU must include Server Authentication or Remote Desktop Authentication, and the SAN the name clients use.",
            "Give NETWORK SERVICE read access to the private key (certlm.msc › the certificate › All Tasks › Manage Private Keys).",
            "Bind it by thumbprint (replace THUMBPRINT with the 40-character value, no spaces). New connections use it immediately.",
            "For many hosts, prefer Group Policy: Remote Desktop Session Host › Security › Server authentication certificate template, with auto-enrolment."].compactMap { $0 },
            commands: ["Get-ChildItem Cert:\\LocalMachine\\My | Where-Object HasPrivateKey | Select-Object Subject, NotAfter, Thumbprint",
                       "\(tsSetting) | Select-Object TerminalName, SSLCertificateSHA1Hash",
                       "\(tsSetting) | Set-CimInstance -Property @{ SSLCertificateSHA1Hash = \(thumb) }",
                       "wmic /namespace:\\\\root\\cimv2\\TerminalServices PATH Win32_TSGeneralSetting Set SSLCertificateSHA1Hash=\"THUMBPRINT\"   # legacy; wmic is deprecated"],
            docs: [KB.rdp, KB.pki])
    }
    public static let rdpSecurity = Guidance(title: "RDP host: require TLS and Network Level Authentication", steps: [
        "Group Policy › Computer Configuration › Administrative Templates › Windows Components › Remote Desktop Services › Remote Desktop Session Host › Security:",
        "'Require use of specific security layer for remote (RDP) connections' = SSL (or Negotiate), and 'Require user authentication for remote connections by using Network Level Authentication' = Enabled.",
        "Or set NLA directly on the host with the command below, then re-check."],
        commands: ["\(tsSetting) | Select-Object TerminalName, SecurityLayer, UserAuthenticationRequired",
                   "\(tsSetting) | Invoke-CimMethod -MethodName SetUserAuthenticationRequired -Arguments @{ UserAuthenticationRequired = 1 }",
                   "gpresult /h \"$env:TEMP\\gp.html\""], docs: [KB.rdp])
    public static func rdgBinding(why: String? = nil) -> Guidance {
        Guidance(title: "RD Gateway: bind the gateway certificate", steps: [why, "Import the certificate (with private key) into Local Computer › Personal. The SAN must contain the public gateway name clients use, and clients must trust the issuing CA.",
            "RD Gateway Manager › the server › Properties › SSL Certificate › Select an existing certificate, or use the commands below.",
            "In an RDS deployment, set it for the RD Gateway role in Server Manager › Deployment Properties › Certificates (Set-RDCertificate)."].compactMap { $0 },
            commands: ["Import-Module RemoteDesktopServices",
                       "Get-Item -Path RDS:\\GatewayServer\\SSLCertificate\\Thumbprint",
                       "Set-Item -Path RDS:\\GatewayServer\\SSLCertificate\\Thumbprint -Value \(thumb)",
                       "Restart-Service TSGateway",
                       "Set-RDCertificate -Role RDGateway -ImportPath 'C:\\path\\gateway.pfx' -Password (Read-Host -AsSecureString) -ConnectionBroker \(Shell.psQuote("broker." + AppConfig.current.defaultDomain)) -Force"],
            docs: [KB.rdGateway, KB.pki])
    }
    public static func winrmListener(host: String, why: String? = nil) -> Guidance {
        let h = Shell.psQuote(host)
        return Guidance(title: "WinRM: HTTPS listener with the right certificate", steps: [why, "The certificate must be in Local Computer › Personal with Server Authentication EKU, and its CN (and SAN) must equal the host name clients use.",
            "Create the HTTPS listener (or update the thumbprint of an existing one), then test from a client without -SkipCACheck/-SkipCNCheck."].compactMap { $0 },
            commands: ["winrm enumerate winrm/config/listener",
                       "New-Item -Path WSMan:\\localhost\\Listener -Transport HTTPS -Address * -HostName \(h) -CertificateThumbPrint \(thumb) -Force",
                       "winrm set winrm/config/Listener?Address=*+Transport=HTTPS '@{CertificateThumbprint=\"THUMBPRINT\"}'",
                       "Test-WSMan -ComputerName \(h) -UseSSL"],
            docs: [KB.winrm, KB.pki])
    }
    public static func winrmHTTP(host: String) -> Guidance {
        Guidance(title: "WinRM: harden or remove the HTTP listener", steps: [
            "Keep Basic authentication off and AllowUnencrypted false on the service.",
            "If nothing needs HTTP (5985), remove that listener after the HTTPS listener works; otherwise restrict 5985 to admin networks in Windows Firewall and on the network firewall."],
            commands: ["Get-Item WSMan:\\localhost\\Service\\AllowUnencrypted, WSMan:\\localhost\\Service\\Auth\\Basic",
                       "Set-Item WSMan:\\localhost\\Service\\Auth\\Basic -Value $false",
                       "Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false",
                       "Get-ChildItem WSMan:\\localhost\\Listener | Where-Object Keys -contains 'Transport=HTTP' | Remove-Item -Recurse   # only after HTTPS works",
                       "Test-WSMan -ComputerName \(Shell.psQuote(host)) -UseSSL"], docs: [KB.winrm])
    }
    public static func firewall(_ s: Service) -> Guidance {
        let port = s == .winrmHTTPS ? 5986 : s.defaultPort
        let name = s == .rdp ? "RDP" : s == .rdGateway ? "RD Gateway" : "WinRM HTTPS"
        return Guidance(title: "Firewall notes (\(name), TCP \(port))", steps: [
            s == .rdGateway ? "RD Gateway is the internet-facing entry point: allow TCP 443 (and UDP 3391 if UDP transport is used) to the gateway only." : "Do not expose \(name) to the internet; allow TCP \(port) only from admin/VPN subnets (or through RD Gateway for RDP).",
            "Check the Windows Firewall rule scope on the host and the matching rule on the network firewall."],
            commands: [s == .rdp ? "Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Get-NetFirewallAddressFilter" : s == .winrmHTTPS ? "Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' | Get-NetFirewallAddressFilter" : "Get-NetFirewallPortFilter | Where-Object LocalPort -eq 443",
                       s == .winrmHTTPS ? "New-NetFirewallRule -DisplayName 'WinRM HTTPS (5986)' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress 'ADMIN_SUBNET' -Action Allow" : "Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -RemoteAddress 'ADMIN_SUBNET'"],
            docs: [KB.pfSense])
    }
    /// Certificate replacement guidance for the remote-admin services (used by Advisor.replace).
    public static func binding(_ s: Service?, host: String, why: String?) -> Guidance? {
        switch s {
        case .rdp: return rdpBinding(why: why)
        case .rdGateway: return rdgBinding(why: why)
        case .winrmHTTPS: return winrmListener(host: host, why: why)
        default: return nil
        }
    }
    public static func guidance(for f: Finding, target: Target?) -> [Guidance] {
        let host = target?.verifyName ?? AppConfig.current.hostPlaceholder
        switch f.kind {
        case "rdp-nla", "rdp-security": return [rdpSecurity, rdpBinding(), firewall(.rdp)]
        case "rdp-cert": return [rdpBinding(), firewall(.rdp)]
        case "rdg-cert": return [rdgBinding(), firewall(.rdGateway)]
        case "winrm-cert": return [winrmListener(host: host), firewall(.winrmHTTPS)]
        case "winrm-http": return f.severity >= .warning ? [winrmHTTP(host: host), winrmListener(host: host), firewall(.winrmHTTPS)] : []
        case "thumb": return target.flatMap { binding($0.service, host: host, why: nil) }.map { [$0] } ?? []
        default: return target.map { [firewall($0.service)] } ?? []
        }
    }
}

/// Form state of the app's Remote access pane, kept in Core so it can be unit tested.
public struct RemoteForm: Equatable {
    public var host = "", service: Service = .rdp, port = "3389", expected = "", checkHTTP = false
    public init() {}
    public mutating func select(_ s: Service) { service = s; port = String(s.defaultPort); if s != .winrmHTTPS { checkHTTP = false } }
    /// The HTTP 5985 check runs only for WinRM and only when the user turned it on.
    public var runsHTTPCheck: Bool { checkHTTP && service == .winrmHTTPS }
    public var canRun: Bool { !host.trimmingCharacters(in: .whitespaces).isEmpty }
    public var target: Target {
        let h = host.trimmingCharacters(in: .whitespaces)
        return Target(name: h, host: h, port: Int(port.trimmingCharacters(in: .whitespaces)) ?? -1, service: service,
                      expectedName: expected.trimmingCharacters(in: .whitespaces), platform: service.windowsPlatform ?? .generic)
    }
}
