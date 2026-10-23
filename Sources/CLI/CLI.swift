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
      certificate-checker registry HOST [--port 443|5000] [--sni NAME] [--expect NAME] [--ca FILE] [--check-v2]
                          (Docker registry certificate; --check-v2 also sends one unauthenticated GET /v2/ on the same TLS connection)
      certificate-checker beats HOST [--port 5044] [--sni NAME] [--expect NAME] [--ca FILE]   (Logstash Beats input TLS certificate)
      certificate-checker es HOST [--port 9200] [--sni NAME] [--expect NAME] [--ca FILE]      (Elasticsearch HTTPS certificate)
                          (--ca: the CA file clients use, e.g. ssl.certificate_authorities; the chain is checked against it offline)
      certificate-checker mtls-pair CERT KEY [MORE...] [--ca FILE]   (Beats client certificate + key: key match, clientAuth EKU, chain to CA; offline)
      certificate-checker smime FILE [--address ADDR]   (S/MIME certificate usage, address, expiry and strength; offline, PEM or DER)
      certificate-checker dkim RECORD-FILE [--key FILE]   (DKIM TXT record: key type, strength, sha1, t=y; --key checks the signing key matches; offline, no DNS query)
      certificate-checker codesign PATH   (.app, binary or .pkg: signature validity, certificate kind and expiry, timestamp, Hardened Runtime; read-only, offline)
      certificate-checker ssh-hostkeys KEYS-FILE [--known-hosts FILE --host NAME [--port 22]]
                      (ssh_host_*_key.pub or saved ssh-keyscan output: weak algorithms, and match against known_hosts incl. hashed entries; offline, no connection)
      certificate-checker munki PLIST [--cert FILE] [--key FILE] [--ca FILE] [--probe-repo]
                          (ManagedInstalls plist offline: SoftwareRepoURL, client certificate/key pair and chain to SoftwareRepoCACertificate;
                           --cert/--key/--ca override the plist paths; --probe-repo also makes one TLS handshake to the SoftwareRepoURL host)
      certificate-checker munki-repo HOST [--port 443] [--sni NAME] [--expect NAME] [--ca FILE]   (Munki repo HTTPS certificate)
      certificate-checker fms HOST [--port 443|5003] [--sni NAME] [--expect NAME]   (FileMaker Server; flags the default "FileMaker" certificate)
      certificate-checker retrospect HOST [--port 443|8443] [--sni NAME] [--expect NAME]
                          (Retrospect self-hosted web console; the Engine 22024 and Client 497 ports are not TLS and are not checked)
      certificate-checker hp-ews HOST [--port 443] [--sni NAME] [--expect NAME]   (HP printer EWS: default cert, key size, negotiated protocol)
      certificate-checker waf HOST [--port 443] [--sni NAME] [--expect NAME]        (Barracuda WAF HTTPS service listener)
      certificate-checker waf-mgmt HOST [--port 8443] [--sni NAME] [--expect NAME]  (Barracuda WAF management UI)
    SERVICE: https tls ldaps ldap-starttls smtp-starttls smtps imap-starttls imaps pop3-starttls pop3s mysql rdp rdg winrm dsm pve pbs registry beats es munki-repo fms retrospect hp-ews waf waf-mgmt
    Read-only. dsm/pve/pbs/beats/es and the vendor checks (munki-repo fms retrospect hp-ews waf waf-mgmt) stop after the TLS handshake (no HTTP request, no login); registry too unless --check-v2. The client certificate is never presented in a handshake (mtls-pair is offline only). For PFX/P12 (macOS 15+; .pfx/.p12 extension, or any file with --pfx) you are prompted for the password without echo. --password-stdin reads one line from piped stdin (prompts hidden instead if stdin is a terminal). Passwords are never stored. CERTCHECK_PFX_PASSWORD is no longer supported. Exit 0 = no failures, 1 = failures, 2 = usage.
    """
    static let services: [String: Service] = ["https": .https, "tls": .tls, "ldaps": .ldaps, "ldap-starttls": .ldapStartTLS, "smtp-starttls": .smtpStartTLS, "smtps": .smtps, "imap-starttls": .imapStartTLS, "imaps": .imaps, "pop3-starttls": .pop3StartTLS, "pop3s": .pop3s, "mysql": .mysql, "rdp": .rdp, "rdg": .rdGateway, "winrm": .winrmHTTPS, "dsm": .synologyDSM, "pve": .proxmoxVE, "pbs": .proxmoxBackup, "registry": .dockerRegistry, "beats": .logstashBeats, "es": .elasticsearch, "munki-repo": .munkiRepo, "fms": .fileMaker, "retrospect": .retrospectConsole, "hp-ews": .hpPrinter, "waf": .barracudaService, "waf-mgmt": .barracudaManagement]

    /// Returns the value after `name` and removes both. Values may not start with "--": a flag followed by another
    /// flag (or nothing) exits 2 with "<name> needs a value", so a host or path that begins with "--" is not accepted.
    static func option(_ args: inout [String], _ name: String) -> String? {
        guard let i = args.firstIndex(of: name) else { return nil }
        // A flag with no value (last argument, or followed by another --flag) is a usage error, not a host name.
        guard i + 1 < args.count, !args[i + 1].hasPrefix("--") else {
            FileHandle.standardError.write("\(name) needs a value\n".data(using: .utf8)!); exit(2)
        }
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
        guard let cmd = args.first, ["file", "probe", "wireguard", "ipsec", "radius", "radius-probe", "rdp", "rdg", "winrm", "dsm", "pve", "pbs", "registry", "beats", "es", "mtls-pair", "munki", "munki-repo", "fms", "retrospect", "hp-ews", "waf", "waf-mgmt", "smime", "dkim", "codesign", "ssh-hostkeys"].contains(cmd) else { print(usage); exit(args.isEmpty || args == ["--help"] ? 0 : 2) }
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
        if cmd == "ssh-hostkeys" {
            let kh = option(&args, "--known-hosts"), host = option(&args, "--host"), port = parsePort(option(&args, "--port")) ?? 22
            guard args.count == 1, !args[0].hasPrefix("--"), (kh == nil) == (host == nil) else { print(usage); exit(2) }
            func read(_ p: String) -> String {
                let u = URL(fileURLWithPath: p)
                guard let a = try? FileManager.default.attributesOfItem(atPath: u.path), (a[.type] as? FileAttributeType) == .typeRegular,
                      ((a[.size] as? NSNumber)?.intValue ?? 0) <= FileCheck.maxFileSize, let d = try? Data(contentsOf: u) else { fputs("Could not read \(p) (regular file, at most 2 MB).\n", stderr); exit(2) }
                return String(decoding: d, as: UTF8.self)
            }
            let keys = SSHHostKeys.parseHostKeys(read(args[0]))
            for k in keys { print("\(k.type) \(k.fingerprint)") }
            let f = SSHHostKeys.inspect(hostKeys: keys, knownHosts: kh.map { SSHHostKeys.parseKnownHosts(read($0)) }, host: host, port: port)
            printFindings(f); exit(f.contains { $0.severity == .fail } ? 1 : 0)
        }
        if cmd == "codesign" {
            guard args.count == 1, !args[0].hasPrefix("--") else { print(usage); exit(2) }
            let i: CodeSign.Info
            do { i = try CodeSign.info(URL(fileURLWithPath: args[0])) } catch { fputs("\(error.localizedDescription)\n", stderr); exit(2) }
            if let id = i.identifier { print("Identifier: \(id)") }
            for (n, c) in i.chain.enumerated() { print("#\(n + 1) \(c.subject.text) · expires \(Analysis.fmt(c.notAfter))") }
            let f = CodeSign.inspect(i)
            printFindings(f); exit(f.contains { $0.severity == .fail } ? 1 : 0)
        }
        if cmd == "dkim" {
            let key = option(&args, "--key").map { URL(fileURLWithPath: $0) }
            guard args.count == 1, !args[0].hasPrefix("--") else { print(usage); exit(2) }
            let r: DKIMRecord, pk: PublicKeyInfo?
            do { r = try DKIM.recordFile(URL(fileURLWithPath: args[0])); pk = try key.map { try DKIM.privateKeyPublicHalf($0) } }
            catch { fputs("\(error.localizedDescription)\n", stderr); exit(2) }
            print("k=\(r.keyType)\(r.publicKey.map { " · \($0.algorithm.description)" } ?? "")")
            let f = DKIM.inspect(r, privateKey: pk)
            printFindings(f); exit(f.contains { $0.severity == .fail } ? 1 : 0)
        }
        if cmd == "smime" {
            let address = option(&args, "--address")
            guard args.count == 1, !args[0].hasPrefix("--") else { print(usage); exit(2) }
            let u = URL(fileURLWithPath: args[0]); let leaf: Certificate
            do {
                let a = try FileManager.default.attributesOfItem(atPath: u.path)
                guard (a[.type] as? FileAttributeType) == .typeRegular, ((a[.size] as? NSNumber)?.intValue ?? 0) <= FileCheck.maxFileSize else { throw CheckError.message("not a regular file of at most 2 MB") }
                let d = try Data(contentsOf: u, options: .uncached)
                let blocks = PEM.blocks(String(decoding: d, as: UTF8.self)).filter { $0.label == "CERTIFICATE" }
                leaf = try Certificate(der: blocks.first?.der ?? [UInt8](d))
            } catch { fputs("Could not read a certificate from \(args[0]): \(error.localizedDescription)\n", stderr); exit(2) }
            print("\(leaf.subject.text) · expires \(Analysis.fmt(leaf.notAfter)) · \(leaf.publicKey.algorithm.description)")
            let f = SMIME.inspect(leaf, address: address)
            printFindings(f); exit(f.contains { $0.severity == .fail } ? 1 : 0)
        }
        if cmd == "munki" {
            let cert = option(&args, "--cert").map { URL(fileURLWithPath: $0) }, key = option(&args, "--key").map { URL(fileURLWithPath: $0) }
            let ca = option(&args, "--ca").map { URL(fileURLWithPath: $0) }
            let probe = args.contains("--probe-repo"); args.removeAll { $0 == "--probe-repo" }
            guard args.count == 1, !args[0].hasPrefix("--") else { print(usage); exit(2) }
            let settings: MunkiSettings
            do {
                settings = try Munki.load(URL(fileURLWithPath: args[0]))
            } catch { fputs("Could not read \(args[0]): \(error.localizedDescription)\n", stderr); exit(2) }
            print("SoftwareRepoURL: \(settings.repoURL ?? "(not set)")")
            print("Note: \(Munki.profileNote)")
            let r = Munki.inspect(settings, cert: cert, key: key, ca: ca)
            for (i, c) in r.chain.enumerated() { print("#\(i + 1) \(c.subject.text) · expires \(Analysis.fmt(c.notAfter)) · \(c.publicKey.algorithm.description)") }
            var findings = r.findings
            if probe {
                if let t = settings.repoTarget {
                    var p = await Probe.run(t)
                    let caURL = ca ?? settings.caCertificate.map { URL(fileURLWithPath: $0) }
                    if let caURL, !p.chain.isEmpty {
                        do { p.findings = Stack.suppliedCA(p.findings, chain: p.chain, ca: try Stack.loadCA([caURL]), hostname: t.verifyName) }
                        catch { p.findings.append(Finding("munki-ca-read", .fail, .vendor, "Could not read SoftwareRepoCACertificate", error.localizedDescription)) }
                    }
                    print("Repo \(t.endpoint)\(p.tlsVersion.map { " · \($0)" } ?? "")")
                    for (i, c) in p.chain.enumerated() { print("  #\(i + 1) \(c.subject.text) · expires \(Analysis.fmt(c.notAfter))") }
                    findings += p.findings.map { var g = $0; g.title = "Repo: " + g.title; return g }
                } else { findings.append(Finding("munki-probe", .info, .vendor, "Repo not probed", "SoftwareRepoURL is not an https:// URL with a host.")) }
            }
            printFindings(findings)
            exit(findings.contains { $0.severity == .fail } ? 1 : 0)
        }
        if cmd == "mtls-pair" {
            var cas: [URL] = []; while let c = option(&args, "--ca") { cas.append(URL(fileURLWithPath: c)) }
            guard args.count >= 2, !args.contains(where: { $0.hasPrefix("--") }) else { print(usage); exit(2) }
            let r = MTLSPair.inspect(args.map { URL(fileURLWithPath: $0) }, ca: cas)
            for (i, c) in r.chain.enumerated() { print("#\(i + 1) \(c.subject.text) · expires \(Analysis.fmt(c.notAfter)) · \(c.publicKey.algorithm.description)") }
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
            let port = parsePort(option(&args, "--port")) ?? 1812
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
        let port = parsePort(option(&args, "--port"))
        let sni = option(&args, "--sni") ?? "", expect = option(&args, "--expect") ?? ""
        let pin = option(&args, "--fingerprint")
        var checkHTTP = false, httpPort = WinRMHTTP.defaultPort
        if cmd == "winrm" {
            checkHTTP = args.contains("--check-http"); args.removeAll { $0 == "--check-http" }
            if let p = option(&args, "--http-port") { guard checkHTTP else { print(usage); exit(2) }; httpPort = parsePort(p)! }
        }
        var checkV2 = false, caFiles: [String] = []
        while let c = option(&args, "--ca") { caFiles.append(c) }
        if args.contains("--check-v2") {
            guard cmd == "registry" || (cmd == "probe" && args.first == "registry") else { print(usage); exit(2) }
            checkV2 = true; args.removeAll { $0 == "--check-v2" }
        }
        if cmd != "probe" { args.insert(cmd, at: 0) }
        guard args.count == 2, let svc = services[args[0]] else { print(usage); exit(2) }
        var t = Target(name: args[1], host: args[1], port: port, service: svc, sni: sni, expectedName: expect)
        if let pin {
            guard svc.acceptsFingerprintPin else { fputs("--fingerprint applies only to pbs and pve.\n", stderr); print(usage); exit(2) }
            guard FingerprintPin.normalize(pin) != nil else { fputs("--fingerprint must be a SHA-256 colon-hex value (AA:BB:…, 32 bytes).\n", stderr); exit(2) }
            t.fingerprintPin = pin
        }
        if !caFiles.isEmpty && !svc.isStack && svc != .munkiRepo { fputs("--ca applies only to registry, beats, es and munki-repo.\n", stderr); print(usage); exit(2) }
        if checkV2 { fputs("Note: --check-v2 sends one unauthenticated GET /v2/ after the handshake (no credentials).\n", stderr) }
        var r = await Probe.run(t, registryAPI: checkV2)
        if !caFiles.isEmpty && !r.chain.isEmpty {
            do { r.findings = Stack.suppliedCA(r.findings, chain: r.chain, ca: try Stack.loadCA(caFiles.map { URL(fileURLWithPath: $0) }), hostname: t.verifyName) }
            catch { fputs("Could not read CA file: \(error.localizedDescription)\n", stderr); exit(2) }
        }
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

/// --port must be an integer 1–65535; anything else is a usage error (exit 2).
func parsePort(_ s: String?) -> Int? {
    guard let s else { return nil }
    guard let p = Int(s), (1...65535).contains(p) else { fputs("--port must be a number 1–65535.\n", stderr); exit(2) }
    return p
}
