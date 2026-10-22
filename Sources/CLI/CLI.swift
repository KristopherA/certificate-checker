import Foundation

@main struct CLI {
    static let usage = """
    Usage:
      certificate-checker [--config PATH] COMMAND ...   (default config: ~/Library/Application Support/CertificateChecker/config.json)
      certificate-checker config [--check]   (show the loaded config; --check exits 1 if a configured KB link is missing)
      certificate-checker file PATH... [--host NAME] [--purpose server|client|any] [--pfx] [--password-stdin]
      certificate-checker wireguard FILE... [--expect-public KEY]   (wg-quick .conf or pfSense config.xml; offline)
      certificate-checker ipsec FILE... [--expect-id FQDN|IP]   (pfSense IKEv2 server/CA PEM, keys, or config.xml; offline)
      certificate-checker radius FILE... [--expect NAME]   (RADIUS EAP server certificate, CA, optional key; offline)
      certificate-checker radius-probe HOST [--port 1812] [--method peap|ttls] [--expect NAME] [--secret-stdin]
                          (one eapol_test attempt, anonymous identity, dummy credentials; shared secret prompted hidden; exit 3 = skipped, eapol_test not installed)
      certificate-checker probe SERVICE HOST [--port N] [--sni NAME] [--expect NAME]
      certificate-checker rdp HOST [--port 3389] [--sni NAME] [--expect NAME]   (X.224 + RDP negotiation, then TLS; no credentials, no CredSSP)
      certificate-checker rdg HOST [--port 443] [--sni NAME] [--expect NAME]    (RD Gateway HTTPS certificate)
      certificate-checker winrm HOST [--port 5986] [--sni NAME] [--expect NAME] [--check-http [--http-port 5985]]
                          (WinRM HTTPS certificate; --check-http also sends one unauthenticated POST /wsman to the PLAINTEXT HTTP listener)
      certificate-checker dsm HOST [--port 5001] [--sni NAME] [--expect NAME]   (Synology DSM HTTPS certificate)
      certificate-checker pve HOST [--port 8006] [--sni NAME] [--expect NAME] [--fingerprint AA:BB:…]   (Proxmox VE web/API certificate)
      certificate-checker pbs HOST [--port 8007] [--sni NAME] [--expect NAME] [--fingerprint AA:BB:…]
                          (Proxmox Backup Server certificate; --fingerprint compares the served SHA-256 fingerprint with your pin)
    SERVICE: https tls ldaps ldap-starttls smtp-starttls smtps imap-starttls imaps pop3-starttls pop3s mysql rdp rdg winrm dsm pve pbs
    Read-only. dsm/pve/pbs stop after the TLS handshake (no HTTP request, no login). For PFX/P12 (macOS 15+; .pfx/.p12 extension, or any file with --pfx) you are prompted for the password without echo. --password-stdin reads one line from piped stdin (prompts hidden instead if stdin is a terminal). Passwords are never stored. CERTCHECK_PFX_PASSWORD is no longer supported. Exit 0 = no failures, 1 = failures, 2 = usage.
    """
    static let services: [String: Service] = ["https": .https, "tls": .tls, "ldaps": .ldaps, "ldap-starttls": .ldapStartTLS, "smtp-starttls": .smtpStartTLS, "smtps": .smtps, "imap-starttls": .imapStartTLS, "imaps": .imaps, "pop3-starttls": .pop3StartTLS, "pop3s": .pop3s, "mysql": .mysql, "rdp": .rdp, "rdg": .rdGateway, "winrm": .winrmHTTPS, "dsm": .synologyDSM, "pve": .proxmoxVE, "pbs": .proxmoxBackup]

    static func option(_ args: inout [String], _ name: String) -> String? {
        guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
        let v = args[i + 1]; args.removeSubrange(i...(i + 1)); return v
    }
    /// Hidden prompt on the controlling terminal via readpassphrase(3); input is not echoed.
    static func promptHidden(_ prompt: String) -> String? {
        var buf = [CChar](repeating: 0, count: 1024)
        guard let p = readpassphrase(prompt, &buf, buf.count, RPP_REQUIRE_TTY) else { return nil }
        let s = String(cString: p)
        for i in buf.indices { buf[i] = 0 }
        return s
    }
    static func printFindings(_ f: [Finding]) {
        for x in f { print("[\(x.severity.label.uppercased())] \(x.title)\(x.detail.isEmpty ? "" : "\n    \(x.detail)")") }
    }
    static func main() async {
        var args = Array(CommandLine.arguments.dropFirst())
        if let i = args.firstIndex(of: "--config") {
            guard i + 1 < args.count else { print(usage); exit(2) }
            AppConfig.use(path: args[i + 1]); args.removeSubrange(i...(i + 1))
        }
        if args.first == "config" {
            let check = args.contains("--check")
            let cfg = AppConfig.current
            print("Config: \(AppConfig.source)")
            if let e = AppConfig.loadError { print("  load error: \(e) (using built-in defaults)") }
            print("  organization: \(cfg.organizationName.isEmpty ? "(none)" : cfg.organizationName)")
            print("  default domain: \(cfg.defaultDomain); placeholders: \(cfg.hostPlaceholder), \(cfg.vpnHostPlaceholder), \(cfg.radiusHostPlaceholder)")
            print("  signing procedure doc: \(cfg.signingProcedureDoc)")
            var missing = 0
            let keys = cfg.kbLinks.keys.sorted()
            print("  KB links: \(keys.isEmpty ? "none (KB buttons hidden)" : String(keys.count))")
            for k in keys {
                let known = KB.allKeys.contains(k)
                let res = KB.resolve(k, config: cfg)
                guard let u = res.url else { print("  INVALID \(k): \(res.problem ?? "unusable link")"); missing += 1; continue }
                if u.isFileURL {
                    let ok = FileManager.default.fileExists(atPath: u.path); if !ok { missing += 1 }
                    print("  \(ok ? "ok     " : "MISSING") \(k)\(known ? "" : " (unknown topic)")" + (check ? "" : " → \(u.path)"))
                } else { print("  url     \(k)\(known ? "" : " (unknown topic)") → \(u.absoluteString)") }
            }
            exit(check && (missing > 0 || AppConfig.loadError != nil) ? 1 : 0)
        }
        guard let cmd = args.first, ["file", "probe", "wireguard", "ipsec", "radius", "radius-probe", "rdp", "rdg", "winrm", "dsm", "pve", "pbs"].contains(cmd) else { print(usage); exit(args.isEmpty || args == ["--help"] ? 0 : 2) }
        args.removeFirst()
        if cmd == "wireguard" {
            let expected = option(&args, "--expect-public")
            guard !args.isEmpty else { print(usage); exit(2) }
            let r = WGCheck.inspect(args.map { URL(fileURLWithPath: $0) }, expectedPublicKey: expected)
            for c in r.configs { print("\(c.name) [\(c.source)] \(c.peers.count) peer(s)\(c.derivedPublicKey.map { " · public key \($0)" } ?? "")") }
            printFindings(r.findings)
            exit(r.findings.contains { $0.severity == .fail } ? 1 : 0)
        }
        if cmd == "ipsec" {
            let id = option(&args, "--expect-id")
            guard !args.isEmpty else { print(usage); exit(2) }
            let r = IPsecCheck.inspect(args.map { URL(fileURLWithPath: $0) }, expectedIdentifier: id)
            for s in r.servers { print("server \(s.label) · \(s.cert.subject.text) · expires \(Analysis.fmt(s.cert.notAfter)) · \(s.cert.publicKey.algorithm.description)") }
            for c in r.cas { print("CA \(c.label) · \(c.cert.subject.text) · expires \(Analysis.fmt(c.cert.notAfter))") }
            printFindings(r.findings)
            exit(r.findings.contains { $0.severity == .fail } ? 1 : 0)
        }
        if cmd == "radius" {
            let name = option(&args, "--expect")
            guard !args.isEmpty else { print(usage); exit(2) }
            let r = RadiusCheck.inspect(args.map { URL(fileURLWithPath: $0) }, expectedName: name)
            for (i, c) in r.chain.enumerated() { print("#\(i + 1) \(c.subject.text) · expires \(Analysis.fmt(c.notAfter)) · \(c.publicKey.algorithm.description)") }
            printFindings(r.findings)
            exit(r.findings.contains { $0.severity == .fail } ? 1 : 0)
        }
        if cmd == "radius-probe" {
            let name = option(&args, "--expect")
            let port = option(&args, "--port").map { Int($0) ?? -1 } ?? 1812
            let method: EAPMethod? = ["peap": .peap, "ttls": .ttls][(option(&args, "--method") ?? "peap").lowercased()]
            let fromStdin = args.contains("--secret-stdin"); args.removeAll { $0 == "--secret-stdin" }
            guard args.count == 1, let method else { print(usage); exit(2) }
            guard let tool = RadiusProbe.locate() else {
                let r = RadiusProbe.run(host: args[0], method: method, expectedName: name, secret: "", tool: nil)
                printFindings(r.findings)
                for g in RadiusAdvisor.install.commands { print("    \(g)") }
                exit(3)
            }
            var secret = fromStdin && isatty(0) == 0 ? (readLine(strippingNewline: true) ?? "") : (promptHidden("RADIUS shared secret: ") ?? "")
            let r = RadiusProbe.run(host: args[0], port: port, method: method, expectedName: name, secret: secret, tool: tool)
            secret = ""
            r.transcript.forEach { print("  \($0)") }
            for (i, c) in r.chain.enumerated() { print("#\(i + 1) \(c.subject.text) · expires \(Analysis.fmt(c.notAfter))") }
            printFindings(r.findings)
            exit(r.findings.contains { $0.severity == .fail } ? 1 : 0)
        }
        if cmd == "file" {
            let host = option(&args, "--host")
            let purpose: Purpose = ["client": .tlsClient, "any": .any][option(&args, "--purpose") ?? ""] ?? .tlsServer
            let fromStdin = args.contains("--password-stdin"); let forcePFX = args.contains("--pfx")
            args.removeAll { $0 == "--password-stdin" || $0 == "--pfx" }
            guard !args.isEmpty else { print(usage); exit(2) }
            if ProcessInfo.processInfo.environment["CERTCHECK_PFX_PASSWORD"] != nil { fputs("Warning: CERTCHECK_PFX_PASSWORD is ignored (environment variables leak to child processes). Use the prompt or --password-stdin.\n", stderr) }
            var password: String?
            if forcePFX || args.contains(where: { ["pfx", "p12"].contains(($0 as NSString).pathExtension.lowercased()) }) {
                password = fromStdin && isatty(0) == 0 ? readLine(strippingNewline: true) : promptHidden("PFX/P12 password: ")
            }
            let r = FileCheck.inspect(args.map { URL(fileURLWithPath: $0) }, hostname: host, purpose: purpose, password: password)
            password = nil
            for (i, c) in r.chain.enumerated() { print("#\(i + 1) \(c.subject.text)\n    issuer \(c.issuer.text)\n    expires \(Analysis.fmt(c.notAfter)) · \(c.publicKey.algorithm.description) · SHA-256 \(c.sha256)") }
            printFindings(r.findings)
            exit(r.findings.contains { $0.severity == .fail } ? 1 : 0)
        }
        let port = option(&args, "--port").map { Int($0) ?? -1 }
        let sni = option(&args, "--sni") ?? "", expect = option(&args, "--expect") ?? ""
        let pin = option(&args, "--fingerprint")
        var checkHTTP = false, httpPort = WinRMHTTP.defaultPort
        if cmd == "winrm" {
            checkHTTP = args.contains("--check-http"); args.removeAll { $0 == "--check-http" }
            if let p = option(&args, "--http-port") { guard checkHTTP, let n = Int(p) else { print(usage); exit(2) }; httpPort = n }
        }
        if cmd != "probe" { args.insert(cmd, at: 0) }
        guard args.count == 2, let svc = services[args[0]] else { print(usage); exit(2) }
        var t = Target(name: args[1], host: args[1], port: port, service: svc, sni: sni, expectedName: expect)
        if let pin {
            guard svc.acceptsFingerprintPin else { fputs("--fingerprint applies only to pbs and pve.\n", stderr); print(usage); exit(2) }
            guard FingerprintPin.normalize(pin) != nil else { fputs("--fingerprint must be a SHA-256 colon-hex value (AA:BB:…, 32 bytes).\n", stderr); exit(2) }
            t.fingerprintPin = pin
        }
        var r = await Probe.run(t)
        if checkHTTP {
            fputs("Warning: checking the WinRM HTTP listener on \(httpPort) uses PLAINTEXT HTTP (one unauthenticated POST /wsman, no credentials).\n", stderr)
            let h = await WinRMHTTP.check(host: t.host, port: httpPort)
            r.transcript += h.transcript; r.findings += h.findings
        }
        r.transcript.forEach { print("  \($0)") }
        if let v = r.tlsVersion { print("Negotiated \(v)") }
        for (i, c) in r.chain.enumerated() { print("#\(i + 1) \(c.subject.text) · expires \(Analysis.fmt(c.notAfter))") }
        printFindings(r.findings)
        exit(r.findings.contains { $0.severity == .fail } ? 1 : 0)
    }
}
