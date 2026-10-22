import Foundation

/// RADIUS server certificate checks for EAP-TLS / PEAP / TTLS (0.4.0).
/// Offline checks read PEM/DER/PKCS#7 files. The live probe wraps eapol_test once (anonymous outer identity, dummy inner
/// credentials, no retries) only to capture the server certificate chain. The shared secret lives in memory only: it is
/// passed to eapol_test with -s, never written to disk, logged, shown, or saved in targets.json.
public enum RadiusCheck {
    public static let appleMaxDays = 825
    static func f(_ id: String, _ s: Severity, _ kind: String, _ title: String, _ detail: String = "") -> Finding { Finding(id, s, .radius, title, detail, kind: kind) }

    public static func inspect(_ urls: [URL], expectedName: String?, now: Date = Date()) -> (chain: [Certificate], findings: [Finding]) {
        var items: [(String, Data)] = []; var pre: [Finding] = []
        for url in urls {
            do {
                let a = try FileManager.default.attributesOfItem(atPath: url.path)
                guard (a[.type] as? FileAttributeType) == .typeRegular else { throw CheckError.message("Not a regular file.") }
                guard ((a[.size] as? NSNumber)?.intValue ?? 0) <= FileCheck.maxFileSize else { throw CheckError.message("File is larger than 2 MB.") }
                items.append((url.lastPathComponent, try Data(contentsOf: url, options: .uncached)))
            } catch { pre.append(f("read-\(url.lastPathComponent)", .fail, "info", "Could not read \(url.lastPathComponent)", error.localizedDescription)) }
        }
        let r = inspect(data: items, expectedName: expectedName, now: now)
        return (r.chain, sort(pre + r.findings))
    }

    public static func inspect(data items: [(name: String, data: Data)], expectedName: String?, now: Date = Date()) -> (chain: [Certificate], findings: [Finding]) {
        var rep = FileReport(); var notes: [Finding] = []
        for (name, data) in items {
            do { try FileCheck.load(name: name, data: data, password: nil, into: &rep) }
            catch { notes.append(f("parse-\(name)", .fail, "info", "Could not parse \(name)", error.localizedDescription)) }
        }
        var seen = Set<String>(); let certs = rep.certificates.filter { seen.insert($0.sha256).inserted }
        let chain = Analysis.orderedChain(certs)
        return (chain, sort(notes + evaluate(chain: chain, keys: rep.keys, expectedName: expectedName, now: now)))
    }

    static func sort(_ f: [Finding]) -> [Finding] { f.sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity } }

    /// `chain` must be leaf-first (Analysis.orderedChain or the order eapol_test received it).
    public static func evaluate(chain: [Certificate], keys: [PublicKeyInfo] = [], expectedName: String?, now: Date = Date()) -> [Finding] {
        guard let leaf = chain.first else { return [f("rad-none", .fail, "info", "No certificate found")] }
        var out: [Finding] = []
        let who = "RADIUS server certificate"
        // Validity
        let days = Int(leaf.notAfter.timeIntervalSince(now) / 86_400)
        if now < leaf.notBefore { out.append(f("rad-valid", .fail, "reissue", "\(who) is not yet valid", "Valid from \(Analysis.fmt(leaf.notBefore)).")) }
        else if now > leaf.notAfter { out.append(f("rad-valid", .fail, "reissue", "\(who) expired \(Analysis.fmt(leaf.notAfter))", "Every 802.1X client will refuse it. Renew and rebind it in NPS/FreeRADIUS.")) }
        else if days <= Analysis.warnDays { out.append(f("rad-valid", .warning, "reissue", "\(who) expires in \(days) day\(days == 1 ? "" : "s")", "Renew now; clients that pinned the old certificate may prompt users.")) }
        else { out.append(f("rad-valid", .pass, "reissue", "\(who) valid for \(days) more days", "Expires \(Analysis.fmt(leaf.notAfter)).")) }
        let lifetime = Int((leaf.notAfter.timeIntervalSince(leaf.notBefore) / 86_400).rounded(.down))
        if !leaf.isSelfIssued && leaf.notBefore >= ChainCheck.appleRuleStart && lifetime > appleMaxDays {
            out.append(f("rad-lifetime", .warning, "reissue", "\(who) lifetime is \(lifetime) days (over 825)", "Apple's 825-day limit is documented for TLS server certificates issued on or after 1 July 2019. Enforcement for 802.1X varies by OS version, so reissue with 825 days or fewer if Apple devices use this network."))
        }
        // EKU
        if let eku = leaf.extendedKeyUsage {
            out.append(eku.contains(OID.serverAuth) ? f("rad-eku", .pass, "reissue", "\(who) has the serverAuth EKU")
                : f("rad-eku", .fail, "reissue", "\(who) lacks the serverAuth EKU", "Present: \(eku.map(OID.name).joined(separator: ", ")). Windows clients reject PEAP/EAP-TLS servers without Server Authentication, and NPS does not offer such certificates."))
        } else { out.append(f("rad-eku", .warning, "reissue", "\(who) has no Extended Key Usage", "Windows expects Server Authentication (1.3.6.1.5.5.7.3.1). Reissue from a template with it.")) }
        if leaf.isCA == true { out.append(f("rad-isca", .fail, "reissue", "\(who) is a CA certificate", "Use an end-entity server certificate (CA:FALSE).")) }
        // Name clients are told to expect
        if let name = expectedName?.trimmingCharacters(in: .whitespaces), !name.isEmpty {
            let m = leaf.matches(hostname: name)
            if m.matched && !m.viaCommonNameOnly { out.append(f("rad-name", .pass, "name", "\(who) covers \(name)")) }
            else if m.matched || leaf.subject.commonName?.lowercased() == name.lowercased() {
                out.append(f("rad-name", .info, "name", "\(name) matches only the Common Name", "Windows ('Connect to these servers'), Android ('Domain') and Apple (TLSTrustedServerNames) accept the CN for 802.1X, but add \(name) to the SAN when reissuing."))
            } else {
                out.append(f("rad-name", .fail, "name", "\(who) does not match \(name)", "Names in certificate: \(([leaf.subject.commonName].compactMap { $0 } + leaf.dnsNames).joined(separator: ", ").ifEmpty("none")). Clients configured to expect \(name) will refuse to connect."))
            }
        } else { out.append(f("rad-name", .info, "name", "No expected server name given", "Enter the name clients are configured to trust (Windows 'Connect to these servers', Android 'Domain', Apple TLSTrustedServerNames).")) }
        // Key and digest
        switch leaf.publicKey.algorithm {
        case .rsa(let b) where b < 2048: out.append(f("rad-key", .fail, "reissue", "\(who) has a weak \(b)-bit RSA key", "Use RSA 2048+ or ECDSA P-256/P-384."))
        case .rsa(let b): out.append(f("rad-key", .pass, "reissue", "\(who) key: RSA \(b)-bit"))
        case .ec(let c) where ["P-256", "P-384", "P-521"].contains(c): out.append(f("rad-key", .pass, "reissue", "\(who) key: ECDSA \(c)"))
        default: out.append(f("rad-key", .warning, "reissue", "\(who) key \(leaf.publicKey.algorithm.description) may not be supported by 802.1X clients", "Use RSA 2048+ or ECDSA P-256/P-384."))
        }
        for (i, c) in chain.enumerated() where !(i > 0 && c.isSelfIssued) {
            let label = i == 0 ? who : "Issuer \(c.displayName)"
            if c.signatureIsWeak { out.append(f("rad-sig-\(i)", .fail, "reissue", "\(label) is signed with \(c.signatureAlgorithm)", "SHA-1/MD5 signatures are rejected by current clients. Reissue with SHA-256 or stronger.")) }
            else if i == 0 { out.append(f("rad-sig-0", .pass, "reissue", "\(who) signature: \(c.signatureAlgorithm)")) }
        }
        // Chain to the CA clients trust
        if chain.count == 1 {
            out.append(leaf.isSelfIssued
                ? f("rad-chain", .warning, "chain", "\(who) is self-signed", "Every client must trust this exact certificate, and must be updated when it is renewed. Prefer a certificate from your internal CA.")
                : f("rad-chain", .warning, "chain", "Issuing CA not supplied", "Issuer: \(leaf.issuer.text). Add the CA clients trust to verify the chain."))
        } else {
            for i in 0..<(chain.count - 1) where chain[i].issuer != chain[i + 1].subject {
                out.append(f("rad-unlinked-\(i)", .fail, "chain", "\(chain[i + 1].displayName) did not issue \(chain[i].displayName)", "The server must send its own certificate followed by the issuing intermediates."))
            }
            for (k, c) in chain.enumerated() where k > 0 && c.isCA != true { out.append(f("rad-notca-\(k)", .fail, "chain", "Issuer \(c.displayName) is not a CA", "Its basicConstraints is not CA:TRUE.")) }
            for (k, c) in chain.enumerated() where k > 0 && now > c.notAfter { out.append(f("rad-caexp-\(k)", .fail, "chain", "Issuer \(c.displayName) expired \(Analysis.fmt(c.notAfter))")) }
            let v = ChainCheck.verify(chain, now: now)
            out.append(v.ok ? f("rad-chain", .pass, "chain", "Chain verifies to \(chain.last!.displayName)", chain.map(\.displayName).joined(separator: " → "))
                            : f("rad-chain", .fail, "chain", "Chain does not verify", v.message))
            if let top = chain.last, !ChainCheck.isSelfSigned(top) { out.append(f("rad-top", .info, "chain", "Chain stops at \(top.displayName)", "Clients must already trust \(top.issuer.text) (normally the root, deployed by GPO/MDM).")) }
        }
        for (k, key) in keys.enumerated() {
            out.append(key.material == leaf.publicKey.material ? f("rad-key-\(k)", .pass, "keymatch", "Private key matches the RADIUS server certificate", "Compared in memory; the key is not shown.")
                                                               : f("rad-key-\(k)", .fail, "keymatch", "Private key does not match the RADIUS server certificate"))
        }
        return out
    }
}

public enum EAPMethod: String, CaseIterable, Identifiable, Codable { case peap = "PEAP", ttls = "TTLS"; public var id: String { rawValue } }

public struct RadiusProbeResult {
    public var transcript: [String] = []
    public var chain: [Certificate] = []
    public var findings: [Finding] = []
    public var skipped = false
}

/// One gentle eapol_test run. Never retries.
public enum RadiusProbe {
    public static let searchPaths = ["/opt/homebrew/bin/eapol_test", "/opt/homebrew/sbin/eapol_test", "/usr/local/bin/eapol_test", "/usr/local/sbin/eapol_test"]
    public static let timeoutSeconds = 15
    static func f(_ id: String, _ s: Severity, _ kind: String, _ title: String, _ detail: String = "") -> Finding { Finding(id, s, .radius, title, detail, kind: kind) }

    public static func locate() -> URL? { searchPaths.first { FileManager.default.isExecutableFile(atPath: $0) }.map(URL.init(fileURLWithPath:)) }

    /// eapol_test network block: anonymous identity, dummy inner password, no ca_cert (we only want the chain the server sends).
    public static func config(_ method: EAPMethod) -> String {
        """
        # Certificate Checker probe: anonymous outer identity, non-existent inner identity and dummy password. Contains no secrets.
        network={
        \tkey_mgmt=IEEE8021X
        \teap=\(method.rawValue)
        \tidentity="certchecker-probe@invalid.example"
        \tanonymous_identity="anonymous"
        \tpassword="certificate-checker-probe-not-a-credential"
        \tphase2="\(method == .peap ? "auth=MSCHAPV2" : "auth=PAP")"
        }

        """
    }

    public static func arguments(config: String, address: String, port: Int, secret: String, certOut: String) -> [String] {
        ["-c", config, "-a", address, "-p", String(port), "-s", secret, "-o", certOut, "-t", String(timeoutSeconds), "-r", "0", "-n"]
    }

    /// Resolve a host name to one numeric address (eapol_test -a takes an IP). A single DNS lookup, nothing else.
    static func resolve(_ host: String) -> String? {
        var a4 = in_addr(), a6 = in6_addr()
        if inet_pton(AF_INET, host, &a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1 { return host }
        var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let r = res else { return nil }
        defer { freeaddrinfo(res) }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard let sa = r.pointee.ai_addr else { return nil }
        return sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in
            var addr = p.pointee.sin_addr
            return inet_ntop(AF_INET, &addr, &buf, socklen_t(buf.count)).map { _ in String(cString: buf) }
        }
    }

    /// Keeps only protocol status lines and removes anything containing the secret or the word "secret".
    public static func redact(_ output: String, secret: String) -> [String] {
        let keep = ["EAP", "RADIUS", "SUCCESS", "FAILURE", "Access-", "TLS", "CTRL-EVENT", "timeout", "Timeout", "No response"]
        return output.split(whereSeparator: \.isNewline).map(String.init)
            .filter { l in keep.contains { l.contains($0) } && !l.lowercased().contains("hexdump") && !l.contains("MPPE") }
            .map { secret.isEmpty ? $0 : $0.replacingOccurrences(of: secret, with: "•••") }
            .filter { !$0.lowercased().contains("secret") }
            .suffix(40).map { String($0.prefix(300)) }
    }

    public static func run(host: String, port: Int = 1812, method: EAPMethod = .peap, expectedName: String?, secret: String,
                           tool: URL? = RadiusProbe.locate(), now: Date = Date(), timeout: Int = RadiusProbe.timeoutSeconds, grace: Int = 5) -> RadiusProbeResult {
        var r = RadiusProbeResult()
        guard let tool else {
            r.skipped = true
            r.findings = [f("rad-probe-tool", .info, "install", "eapol_test is not installed; live probe skipped", "Install it (see How to fix) and run the probe again. Offline file checks still work.")]
            return r
        }
        guard Target.validHost(host), (1...65535).contains(port) else { r.findings = [f("rad-probe-input", .fail, "probe", "Invalid host or port")]; return r }
        guard !secret.isEmpty, !secret.contains("\0"), secret.utf8.count <= 128 else { r.findings = [f("rad-probe-input", .fail, "probe", "Shared secret must be 1–128 characters")]; return r }
        guard let address = resolve(host) else { r.findings = [f("rad-probe-dns", .fail, "probe", "\(host) did not resolve to an IPv4 address", "Name resolution is IPv4-only (eapol_test needs a numeric address). Check DNS, or enter the server IP; IPv6 literals are passed through as entered.")]; return r }
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("certchecker-radius-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: dir) }
        do {
            try fm.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let conf = dir.appendingPathComponent("eapol.conf"), certs = dir.appendingPathComponent("server-chain.pem")
            guard fm.createFile(atPath: conf.path, contents: Data(config(method).utf8), attributes: [.posixPermissions: 0o600]) else { throw CheckError.message("Could not write the temporary eapol_test config.") }
            let p = Process(); p.executableURL = tool
            p.arguments = arguments(config: conf.path, address: address, port: port, secret: secret, certOut: certs.path)
            if let i = p.arguments?.firstIndex(of: "-t") { p.arguments?[i + 1] = String(timeout) }
            let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe; p.standardInput = FileHandle.nullDevice
            var output = Data(); let lock = NSLock()
            pipe.fileHandleForReading.readabilityHandler = { h in let d = h.availableData; lock.lock(); if output.count < 1_000_000 { output.append(d) }; lock.unlock() }
            let done = DispatchSemaphore(value: 0)
            let reader = pipe.fileHandleForReading
            p.terminationHandler = { _ in reader.readabilityHandler = nil; done.signal() }
            try p.run()
            var timedOut = false
            var killed = false
            if done.wait(timeout: .now() + .seconds(timeout + grace)) == .timedOut {
                timedOut = true; p.terminate()
                if done.wait(timeout: .now() + 2) == .timedOut { kill(p.processIdentifier, SIGKILL); killed = true; _ = done.wait(timeout: .now() + 2) }
            }
            reader.readabilityHandler = nil
            // After a timeout, children may still hold the pipe open: keep what was already read instead of blocking.
            if !timedOut { let rest = reader.readDataToEndOfFile(); lock.lock(); output.append(rest); lock.unlock() }
            try? reader.close()
            lock.lock(); let text = String(decoding: output, as: UTF8.self); lock.unlock()
            r.transcript = ["eapol_test \(method.rawValue) → \(host)\(address == host ? "" : " (\(address))"):\(port), one attempt"] + redact(text, secret: secret)
            if timedOut { r.findings.append(f("rad-probe-timeout", .fail, "probe", "eapol_test did not finish in \(timeout + grace) s and was \(killed ? "killed (SIGKILL after ignoring SIGTERM)" : "stopped")")) }
            if let data = fm.contents(atPath: certs.path), !data.isEmpty {
                var rep = FileReport(); try? FileCheck.load(name: "server-chain.pem", data: data, password: nil, into: &rep)
                r.chain = rep.certificates   // eapol_test writes the chain in the order the server sent it (leaf first)
            }
            if r.chain.isEmpty {
                r.findings.append(f("rad-probe-nocert", .fail, "probe", "No server certificate was received",
                    "Check that this Mac's IP is a RADIUS client (NAS) on the server, the shared secret, and that UDP \(port) is allowed. A wrong secret usually looks like no response."))
            } else {
                r.findings.append(f("rad-probe-ok", .info, "probe", "Received \(r.chain.count) certificate\(r.chain.count == 1 ? "" : "s") from the server", "The authentication itself is expected to fail: the probe uses dummy credentials."))
                if Analysis.orderedChain(r.chain).map(\.sha256) != r.chain.map(\.sha256) { r.findings.append(f("rad-order", .warning, "chain", "Server sends its chain out of order", "Send the server certificate first, then each intermediate.")) }
                r.findings += RadiusCheck.evaluate(chain: r.chain, expectedName: expectedName, now: now)
            }
        } catch { r.findings.append(f("rad-probe-run", .fail, "probe", "eapol_test could not be run", error.localizedDescription)) }
        r.findings = RadiusCheck.sort(r.findings)
        return r
    }
}

/// Copy-only guidance. The app never runs these commands.
public enum RadiusAdvisor {
    public static let docs = [KB.radiusGuide, KB.radiusWifi, KB.radius8021xAD, KB.pki]
    public static func guidance(for f: Finding, platform: Platform) -> [Guidance] {
        if f.kind == "install" { return [install] }
        let nps = Guidance(title: "Windows NPS", steps: [
            "certlm.msc › Personal › Certificates: the server certificate must have Server Authentication, the name clients expect, and its private key.",
            "NPS console › Policies › Network Policies › (wireless policy) › Constraints › Authentication Methods › Microsoft: Protected EAP (PEAP) › Edit: choose the new certificate under 'Certificate issued to'. Repeat for Connection Request Policies that override authentication.",
            "For a probe, the Mac's IP must be listed under RADIUS Clients and Servers › RADIUS Clients.",
            "Update clients' trusted server names/CA (GPO or MDM) before swapping the certificate."],
            commands: ["Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1' } | Format-List Subject,DnsNameList,NotAfter,Thumbprint", "netsh nps show client", "Restart-Service IAS"], docs: docs)
        let linux = Guidance(title: "FreeRADIUS on Linux", steps: [
            "Edit /etc/freeradius/3.0/mods-available/eap (RHEL: /etc/raddb/mods-available/eap), tls-config tls-common: certificate_file = server certificate followed by intermediates, private_key_file = its key (mode 640, group freerad/radiusd), ca_file = the CA chain.",
            "Check the configuration, then restart.", "For a probe, add the Mac's IP as a client in clients.conf."],
            commands: ["sudo freeradius -XC", "sudo openssl x509 -in /etc/freeradius/3.0/certs/server.pem -noout -subject -enddate -ext subjectAltName,extendedKeyUsage", "sudo systemctl restart freeradius"], docs: docs)
        let pf = Guidance(title: "pfSense FreeRADIUS package", steps: [
            "System › Cert. Manager: import or issue the server certificate (Certificate Type: Server Certificate) under the CA clients trust.",
            "Services › FreeRADIUS › EAP: set SSL Server Certificate and SSL CA Certificate, Save.",
            "Services › FreeRADIUS › NAS / Clients: add the Mac's IP to run a probe.",
            "Run the commands below in Diagnostics › Command Prompt, or an SSH shell (menu option 8)."],
            commands: ["/usr/local/sbin/radiusd -XC", "for f in /usr/local/etc/raddb/certs/*.pem; do openssl x509 -in \"$f\" -noout -subject -enddate 2>/dev/null; done"], docs: docs)
        switch platform {
        case .windowsAD, .windowsIIS: return [nps, linux, pf]
        case .pfSense: return [pf, nps, linux]
        default: return [linux, nps, pf]
        }
    }
    public static let install = Guidance(title: "Install eapol_test (copy-only, not yet verified on this Mac)", steps: [
        "eapol_test is part of wpa_supplicant. First check whether Homebrew (or a tap you trust) offers it.",
        "Otherwise build it from the official wpa_supplicant source (w1.fi). This recipe is not yet verified on this Mac: the Linux-only nl80211/libnl driver options are commented out and OpenSSL 3 from Homebrew is used.",
        "Install it to /usr/local/bin or /opt/homebrew/bin; Certificate Checker looks only in those folders."],
        commands: ["brew search eapol_test",
                   "curl -LO https://w1.fi/releases/wpa_supplicant-2.11.tar.gz && tar xzf wpa_supplicant-2.11.tar.gz && cd wpa_supplicant-2.11/wpa_supplicant",
                   "cp defconfig .config && sed -i '' -e 's/^CONFIG_DRIVER_NL80211=y/#CONFIG_DRIVER_NL80211=y/' -e 's/^CONFIG_LIBNL32=y/#CONFIG_LIBNL32=y/' .config && printf 'CONFIG_TLS=openssl\\nCONFIG_EAPOL_TEST=y\\n' >> .config",
                   "make eapol_test EXTRA_CFLAGS=\"-I$(brew --prefix openssl@3)/include\" LDFLAGS=\"-L$(brew --prefix openssl@3)/lib\"",
                   "sudo install -d /usr/local/bin && sudo install -m 755 eapol_test /usr/local/bin/eapol_test"], docs: [])
}
