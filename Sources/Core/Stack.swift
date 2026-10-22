import Foundation

// MARK: Docker registry (/v2/, 443 or 5000), Logstash Beats input (5044), Elasticsearch (9200) and Beats client mTLS (0.7.0).
// One TLS handshake per check. The registry check may add one unauthenticated GET /v2/ on the same TLS connection, only when
// explicitly requested (--check-v2 / the app toggle), the same opt-in pattern as the WinRM --check-http listener check.
// The client certificate is NOT presented in a handshake: macOS needs a SecIdentity for that, which in practice means
// importing the private key into a keychain, and keys stay in memory only. Client pairs are validated offline instead.

public enum Stack {
    static func f(_ id: String, _ s: Severity, _ kind: String, _ title: String, _ detail: String = "") -> Finding { Finding(id, s, .stack, title, detail, kind: kind) }
    static func sort(_ f: [Finding]) -> [Finding] { f.sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity } }

    /// Elasticsearch 8 security auto-configuration creates its own HTTP CA ("Elasticsearch security auto-configuration HTTP CA").
    public static func isElasticAutoConfigured(_ leaf: Certificate, chain: [Certificate]) -> Bool {
        ([leaf.issuer.commonName] + chain.map(\.subject.commonName)).compactMap { $0 }.contains { $0.localizedCaseInsensitiveContains("Elasticsearch security auto-configuration") }
    }

    /// Product notes added inside Probe.runSync for the three stack services.
    public static func adjust(_ findings: [Finding], chain: [Certificate], target: Target) -> [Finding] {
        guard let leaf = chain.first, target.service.isStack else { return findings }
        var out = findings
        switch target.service {
        case .dockerRegistry:
            out.append(f("reg-tls", .info, "registry-cert", "Docker registry TLS endpoint \(target.endpoint)", "Docker validates this chain against the system store plus /etc/docker/certs.d/\(target.verifyName)\(target.port == 443 ? "" : ":\(target.port)")/ca.crt. Never use insecure-registries to work around a certificate problem."))
        case .logstashBeats:
            out.append(f("beats-tls", .info, "beats-tls", "Logstash Beats input TLS on \(target.endpoint)", "Beats trust this certificate through ssl.certificate_authorities in filebeat.yml (output.logstash). Use --ca to check the chain against that CA file."))
        case .elasticsearch:
            if isElasticAutoConfigured(leaf, chain: chain) {
                out.append(f("es-autoca", .warning, "es-cert", "Elasticsearch auto-configured HTTP CA", "Issued by \(leaf.issuer.commonName ?? leaf.issuer.text). Clients must be given http_ca.crt (ssl.certificate_authorities or ca_trusted_fingerprint); browsers and other tools will not trust it. Replace it with a certificate from your CA for long-lived deployments."))
            } else {
                out.append(f("es-tls", .info, "es-cert", "Elasticsearch HTTPS on \(target.endpoint)", "Beats output.elasticsearch trusts this certificate through ssl.certificate_authorities. Use --ca to check the chain against that CA file."))
            }
        default: break
        }
        return sort(out)
    }

    /// Note added when the handshake to a Beats/Elasticsearch port fails: the server may require a client certificate.
    public static func handshakeFailureNote(_ t: Target) -> Finding? {
        guard t.service == .logstashBeats || t.service == .elasticsearch else { return nil }
        return f("mtls-required", .info, "mtls-client", "The server may require a client certificate", "If \(t.service == .logstashBeats ? "the beats input sets ssl_client_authentication => \"required\"" : "xpack.security.http.ssl.client_authentication is required") the handshake fails without one. This checker never presents a client certificate (keys stay in memory only); validate the Beats client pair offline instead.")
    }

    /// Compares the presented chain with the CA file the clients are configured with (ssl.certificate_authorities).
    /// The macOS "trust" failure is downgraded to info ONLY when the untrusted root is the sole problem: the chain verifies
    /// to the supplied CA (signatures), every certificate on that path is inside its validity dates, and the leaf covers
    /// `hostname` by SAN. Expiry, a bad signature or a hostname mismatch therefore still fail.
    public static func suppliedCA(_ findings: [Finding], chain: [Certificate], ca: [Certificate], hostname: String?, now: Date = Date()) -> [Finding] {
        guard let leaf = chain.first, !ca.isEmpty else { return findings }
        var out = findings + nonCAWarnings(ca)
        let v = verifies(leaf: leaf, intermediates: Array(chain.dropFirst()), ca: ca, now: now)
        if v.ok {
            out.append(f("ca-chain", .pass, "ca-chain", "Chains to the supplied CA \(v.path.last?.displayName ?? "")", v.path.map(\.displayName).joined(separator: " → ")))
            let inValidity = v.path.allSatisfy { $0.notBefore <= now && now <= $0.notAfter }
            let nameOK = hostname.map { h in let m = leaf.matches(hostname: h); return m.matched && !m.viaCommonNameOnly } ?? false
            if let i = out.firstIndex(where: { $0.id == "trust" }), out[i].severity == .fail, inValidity, nameOK {
                out[i].severity = .info; out[i].detail += " Clients configured with the supplied CA file trust it."
            }
        } else {
            out.append(f("ca-chain", .fail, "ca-chain", "Does not chain to the supplied CA", v.message))
        }
        return sort(out)
    }

    /// CA-file entries that are not CA certificates (basicConstraints CA:TRUE missing): clients ignore them as anchors.
    public static func nonCAWarnings(_ ca: [Certificate]) -> [Finding] {
        ca.enumerated().filter { $0.element.isCA != true }.map { k, c in
            f("ca-nonca-\(k)", .warning, "ca-chain", "CA file contains a non-CA certificate: \(c.displayName)", "It lacks basicConstraints CA:TRUE, so it cannot act as a trust anchor for ssl.certificate_authorities / certs.d. Put only the issuing CA certificates in this file.")
        }
    }

    /// Reads CA files (regular files ≤ 2 MB, PEM/DER/PKCS#7) for the --ca / app CA comparison. Non-CA certificates are kept
    /// but reported by `nonCAWarnings` (added by suppliedCA and the mTLS pair check).
    public static func loadCA(_ urls: [URL]) throws -> [Certificate] {
        var rep = FileReport()
        for url in urls {
            let a = try FileManager.default.attributesOfItem(atPath: url.path)
            guard (a[.type] as? FileAttributeType) == .typeRegular else { throw CheckError.message("\(url.lastPathComponent): not a regular file.") }
            guard ((a[.size] as? NSNumber)?.intValue ?? 0) <= FileCheck.maxFileSize else { throw CheckError.message("\(url.lastPathComponent): larger than 2 MB.") }
            try FileCheck.load(name: url.lastPathComponent, data: Data(contentsOf: url, options: .uncached), password: nil, into: &rep)
        }
        guard !rep.certificates.isEmpty else { throw CheckError.message("No certificate in the CA file.") }
        return rep.certificates
    }

    /// Builds leaf → … → a certificate from `ca`, then verifies signatures with that CA as the only anchor (no network).
    static func verifies(leaf: Certificate, intermediates: [Certificate], ca: [Certificate], now: Date) -> (ok: Bool, path: [Certificate], message: String) {
        let caHashes = Set(ca.map(\.sha256))
        var path = ChainCheck.chain(for: leaf, pool: intermediates.filter { !caHashes.contains($0.sha256) } + ca)
        if let k = path.firstIndex(where: { caHashes.contains($0.sha256) }) { path = Array(path[...k]) }
        guard let top = path.last, caHashes.contains(top.sha256), path.count > 1 || caHashes.contains(leaf.sha256) else {
            return (false, path, "Issuer \(path.last?.issuer.text ?? leaf.issuer.text) is not in the supplied CA file (\(ca.map(\.displayName).joined(separator: ", "))).")
        }
        let r = ChainCheck.verify(path, now: now)
        return (r.ok, path, r.ok ? "" : r.message)
    }
}

// MARK: Registry API: one unauthenticated GET /v2/ over the already-established TLS connection.

public enum RegistryAPI {
    public static func request(host: String, port: Int) -> String {
        let h = host.contains(":") ? "[\(host)]" : host
        return "GET /v2/ HTTP/1.1\r\nHost: \(h)\(port == 443 ? "" : ":\(port)")\r\nUser-Agent: certificate-checker\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    }
    public struct Response: Equatable { public let status: Int; public let apiVersion: String?; public let schemes: [String] }
    public static func parse(_ lines: [String]) -> Response? {
        guard let first = lines.first, first.hasPrefix("HTTP/1."), let code = Int(first.split(separator: " ").dropFirst().first ?? "") else { return nil }
        var api: String?, schemes: [String] = []
        for l in lines.dropFirst() {
            guard let c = l.firstIndex(of: ":") else { continue }
            let k = l[..<c].lowercased(), v = l[l.index(after: c)...].trimmingCharacters(in: .whitespaces)
            if k == "docker-distribution-api-version" { api = Wire.sanitize(v) }
            if k == "www-authenticate", let s = v.split(separator: " ").first { schemes.append(Wire.sanitize(String(s))) }
        }
        return Response(status: code, apiVersion: api, schemes: schemes)
    }
    public static func findings(_ r: Response?, error: String? = nil) -> [Finding] {
        if let error { return [Stack.f("reg-v2", .info, "registry-api", "GET /v2/ was not answered", error)] }
        guard let r else { return [Stack.f("reg-v2", .warning, "registry-api", "The TLS endpoint did not answer GET /v2/ with HTTP", "Check the port: a registry usually listens on 443 (behind a proxy) or 5000.")] }
        let api = r.apiVersion.map { " (Docker-Distribution-Api-Version: \($0))" } ?? ""
        switch r.status {
        case 401:
            let basic = r.schemes.contains { $0.caseInsensitiveCompare("Basic") == .orderedSame }
            return [Stack.f("reg-v2", .pass, "registry-api", "Registry v2 API answers and requires authentication\(api)", "Offered: \(r.schemes.joined(separator: ", ").ifEmpty("no WWW-Authenticate header")).\(basic ? " Basic credentials are protected only by this TLS connection: keep the certificate valid and trusted." : "")")]
        case 200:
            return [Stack.f("reg-v2", .warning, "registry-api", "Registry v2 API allows anonymous access\(api)", "GET /v2/ returned 200 without credentials. Anyone who reaches \(r.apiVersion == nil ? "this endpoint" : "the registry") can list and pull. Add authentication (htpasswd or token auth) unless the registry is meant to be public.")]
        case 404:
            return [Stack.f("reg-v2", .warning, "registry-api", "GET /v2/ returned 404: not a Docker registry v2 endpoint", "Check the host and port, or the reverse-proxy location for /v2/.")]
        default:
            return [Stack.f("reg-v2", r.apiVersion == nil ? .warning : .info, "registry-api", "GET /v2/ returned \(r.status)\(api)", r.apiVersion == nil ? "No Docker-Distribution-Api-Version header: this may not be a registry." : "")]
        }
    }
}

// MARK: Offline Beats client certificate + key validation against a CA (in memory only).

public enum MTLSPair {
    /// Reads certificate, key and CA files (≤ 2 MB each). Keys are compared in memory and never printed.
    public static func inspect(_ urls: [URL], ca caURLs: [URL], now: Date = Date()) -> (chain: [Certificate], findings: [Finding]) {
        func read(_ list: [URL], _ pre: inout [Finding]) -> [(String, Data)] {
            list.compactMap { url in
                do {
                    let a = try FileManager.default.attributesOfItem(atPath: url.path)
                    guard (a[.type] as? FileAttributeType) == .typeRegular else { throw CheckError.message("Not a regular file.") }
                    guard ((a[.size] as? NSNumber)?.intValue ?? 0) <= FileCheck.maxFileSize else { throw CheckError.message("File is larger than 2 MB.") }
                    return (url.lastPathComponent, try Data(contentsOf: url, options: .uncached))
                } catch { pre.append(Stack.f("read-\(url.lastPathComponent)", .fail, "info", "Could not read \(url.lastPathComponent)", error.localizedDescription)); return nil }
            }
        }
        var pre: [Finding] = []
        let items = read(urls, &pre), caItems = read(caURLs, &pre)
        let r = inspect(data: items, ca: caItems, now: now)
        return (r.chain, Stack.sort(pre + r.findings))
    }

    public static func inspect(data items: [(name: String, data: Data)], ca caItems: [(name: String, data: Data)], now: Date = Date()) -> (chain: [Certificate], findings: [Finding]) {
        var rep = FileReport(), caRep = FileReport(); var notes: [Finding] = []
        for (name, data) in items {
            do { try FileCheck.load(name: name, data: data, password: nil, into: &rep) }
            catch { notes.append(Stack.f("parse-\(name)", .fail, "info", "Could not parse \(name)", error.localizedDescription)) }
        }
        for (name, data) in caItems {
            do { try FileCheck.load(name: name, data: data, password: nil, into: &caRep) }
            catch { notes.append(Stack.f("parse-ca-\(name)", .fail, "info", "Could not parse CA file \(name)", error.localizedDescription)) }
        }
        var seen = Set<String>(); let certs = rep.certificates.filter { seen.insert($0.sha256).inserted }
        let ca = caRep.certificates
        let r = evaluate(certs: certs, keys: rep.keys, ca: ca, now: now)
        return (r.chain, Stack.sort(notes + r.findings))
    }

    public static func evaluate(certs: [Certificate], keys: [PublicKeyInfo], ca: [Certificate], now: Date = Date()) -> (chain: [Certificate], findings: [Finding]) {
        // The client certificate is the first non-CA certificate; any others are intermediates.
        guard let leaf = certs.first(where: { $0.isCA != true }) ?? certs.first else { return ([], [Stack.f("mtls-none", .fail, "mtls-client", "No client certificate found")]) }
        let who = "Client certificate \(leaf.displayName)"
        var out: [Finding] = []
        let days = Int(leaf.notAfter.timeIntervalSince(now) / 86_400)
        if now < leaf.notBefore { out.append(Stack.f("mtls-valid", .fail, "mtls-client", "\(who) is not yet valid", "Valid from \(Analysis.fmt(leaf.notBefore)).")) }
        else if now > leaf.notAfter { out.append(Stack.f("mtls-valid", .fail, "mtls-client", "\(who) expired \(Analysis.fmt(leaf.notAfter))", "The Logstash beats input / Elasticsearch will reject the handshake.")) }
        else if days <= Analysis.warnDays { out.append(Stack.f("mtls-valid", .warning, "mtls-client", "\(who) expires in \(days) day\(days == 1 ? "" : "s")")) }
        else { out.append(Stack.f("mtls-valid", .pass, "mtls-client", "\(who) valid for \(days) more days", "Expires \(Analysis.fmt(leaf.notAfter)).")) }
        if leaf.isCA == true { out.append(Stack.f("mtls-isca", .fail, "mtls-client", "\(who) is a CA certificate", "Use an end-entity certificate (CA:FALSE).")) }
        if let eku = leaf.extendedKeyUsage {
            if eku.contains(OID.clientAuth) { out.append(Stack.f("mtls-eku", .pass, "mtls-client", "\(who) has the clientAuth EKU")) }
            else if eku.contains(OID.anyEKU) { out.append(Stack.f("mtls-eku", .fail, "mtls-client", "\(who) has anyExtendedKeyUsage instead of clientAuth", "anyExtendedKeyUsage (2.5.29.37.0) does not name TLS Web Client Authentication. RFC 5280 says applications that require a specific purpose may reject it, and validators differ on whether they accept it in place of clientAuth, so the Logstash beats input / Elasticsearch may refuse the handshake. Reissue with extendedKeyUsage=clientAuth.")) }
            else { out.append(Stack.f("mtls-eku", .fail, "mtls-client", "\(who) lacks the clientAuth EKU", "Present: \(eku.map(OID.name).joined(separator: ", ")). Java (Logstash, Elasticsearch) rejects client certificates whose EKU excludes TLS Web Client Authentication. Reissue with extendedKeyUsage=clientAuth.")) }
        } else { out.append(Stack.f("mtls-eku", .info, "mtls-client", "\(who) has no Extended Key Usage", "Accepted for any purpose; prefer extendedKeyUsage=clientAuth when reissuing.")) }
        if keys.isEmpty { out.append(Stack.f("mtls-key", .warning, "mtls-key", "No private key supplied", "Add the key file named by ssl.key in filebeat.yml to confirm it matches.")) }
        for (k, key) in keys.enumerated() {
            out.append(key.material == leaf.publicKey.material
                ? Stack.f("mtls-key-\(k)", .pass, "mtls-key", "Private key matches the client certificate", "Compared in memory; the key is not shown.")
                : Stack.f("mtls-key-\(k)", .fail, "mtls-key", "Private key does not match the client certificate", "ssl.certificate and ssl.key must be a pair. The handshake fails with a signature or bad-certificate error."))
        }
        var chain = [leaf]
        if ca.isEmpty {
            out.append(Stack.f("mtls-ca", .warning, "mtls-ca", "No CA supplied", "Add the CA the server trusts for clients (Logstash ssl_certificate_authorities, Elasticsearch xpack.security.http.ssl.certificate_authorities) with --ca."))
        } else {
            out += Stack.nonCAWarnings(ca)
            let v = Stack.verifies(leaf: leaf, intermediates: certs.filter { $0.sha256 != leaf.sha256 }, ca: ca, now: now)
            chain = v.path
            out.append(v.ok ? Stack.f("mtls-ca", .pass, "mtls-ca", "Client certificate chains to the supplied CA \(v.path.last?.displayName ?? "")", v.path.map(\.displayName).joined(separator: " → "))
                            : Stack.f("mtls-ca", .fail, "mtls-ca", "Client certificate does not chain to the supplied CA", v.message))
        }
        out.append(Stack.f("mtls-handshake", .info, "mtls-client", "Client certificate not presented in a live handshake", "Not implemented: presenting it needs a macOS SecIdentity, which means importing the private key into a keychain. Keys stay in memory only, so only this offline check is done."))
        return (chain, Stack.sort(out))
    }
}

// MARK: Copy-only guidance

public enum StackAdvisor {
    public static func registry(host: String, port: Int, why: String? = nil) -> Guidance {
        let hp = port == 443 ? host : "\(host):\(port)"
        return Guidance(title: "Docker registry: certificate and client trust", steps: [why,
            "Registry (distribution) config.yml: http.tls.certificate is the full chain (leaf first), http.tls.key its key. Or set REGISTRY_HTTP_TLS_CERTIFICATE / REGISTRY_HTTP_TLS_KEY.",
            "Behind a reverse proxy, the proxy serves the certificate instead: fix it there.",
            "Each Docker host that pulls from a private-CA registry needs the CA at /etc/docker/certs.d/\(hp)/ca.crt (no daemon restart needed).",
            "Do not add the registry to insecure-registries in daemon.json."].compactMap { $0 },
            commands: ["sudo mkdir -p /etc/docker/certs.d/\(Shell.quote(hp)) && sudo cp ca.crt /etc/docker/certs.d/\(Shell.quote(hp))/ca.crt",
                       "docker run -d -p 5000:5000 -v \"$PWD/certs:/certs\" -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/fullchain.pem -e REGISTRY_HTTP_TLS_KEY=/certs/registry.key registry:2",
                       "\(Shell.openssl) s_client -connect \(Shell.quote(host + ":" + String(port))) -servername \(Shell.quote(host)) -showcerts </dev/null",
                       "curl -sI --cacert ca.crt \(Shell.quote("https://" + hp + "/v2/"))"],
            docs: [KB.pki])
    }
    public static func logstash(why: String? = nil) -> Guidance {
        Guidance(title: "Logstash beats input: TLS settings", steps: [why,
            "In the pipeline's beats input set ssl_enabled, ssl_certificate (leaf + intermediates) and ssl_key (PKCS#8 PEM). Logstash 8 renamed ssl to ssl_enabled and ssl_verify_mode to ssl_client_authentication.",
            "For mTLS add ssl_certificate_authorities (the CA that issued the Beats client certificates) and ssl_client_authentication => \"required\".",
            "Restart Logstash after changing the pipeline."].compactMap { $0 },
            commands: ["input {\n  beats {\n    port => 5044\n    ssl_enabled => true\n    ssl_certificate => \"/etc/logstash/certs/logstash.crt\"\n    ssl_key => \"/etc/logstash/certs/logstash.pkcs8.key\"\n    ssl_certificate_authorities => [\"/etc/logstash/certs/ca.crt\"]\n    ssl_client_authentication => \"required\"\n  }\n}",
                       "openssl pkcs8 -topk8 -nocrypt -in logstash.key -out logstash.pkcs8.key   # Logstash needs PKCS#8"],
            docs: [KB.pki])
    }
    public static func filebeat(output: String = "logstash", why: String? = nil) -> Guidance {
        let hosts = output == "logstash" ? "\"logstash.example.test:5044\"" : "\"https://es.example.test:9200\""
        return Guidance(title: "Filebeat: \(output == "logstash" ? "output.logstash" : "output.elasticsearch") ssl.* settings", steps: [why,
            "ssl.certificate_authorities: the CA that issued the server certificate (Elasticsearch 8 auto-config: http_ca.crt).",
            "For mTLS: ssl.certificate and ssl.key: the Beats client certificate (clientAuth EKU) and its key.",
            "Keep ssl.verification_mode: full (the default). 'none' disables certificate checking.",
            "Test with filebeat test output before restarting."].compactMap { $0 },
            commands: ["output.\(output):\n  hosts: [\(hosts)]\n  ssl.certificate_authorities: [\"/etc/filebeat/certs/ca.crt\"]\n  ssl.certificate: \"/etc/filebeat/certs/beats.crt\"\n  ssl.key: \"/etc/filebeat/certs/beats.key\"\n  ssl.verification_mode: full",
                       "filebeat test output",
                       "\(Shell.openssl) verify -CAfile ca.crt -purpose sslclient beats.crt"],
            docs: [KB.pki])
    }
    public static func elasticsearch(why: String? = nil) -> Guidance {
        Guidance(title: "Elasticsearch: HTTP layer certificate", steps: [why,
            "elasticsearch.yml: xpack.security.http.ssl.enabled: true with keystore.path (PKCS#12) or certificate + key + certificate_authorities (PEM).",
            "For client certificates on the HTTP layer set xpack.security.http.ssl.client_authentication: optional or required.",
            "Elasticsearch 8 auto-configuration writes certs/http.p12 and http_ca.crt: give clients http_ca.crt, or replace with a certificate from your CA.",
            "Restart each node after replacing files."].compactMap { $0 },
            commands: ["xpack.security.http.ssl:\n  enabled: true\n  certificate: certs/es.crt\n  key: certs/es.key\n  certificate_authorities: [ \"certs/ca.crt\" ]\n  client_authentication: optional",
                       "bin/elasticsearch-certutil http   # interactive CSR or certificate bundle for the HTTP layer",
                       "\(Shell.openssl) x509 -fingerprint -sha256 -noout -in http_ca.crt   # ca_trusted_fingerprint for Beats"],
            docs: [KB.pki])
    }
    public static func binding(_ s: Service?, host: String, port: Int?, why: String?) -> Guidance? {
        switch s {
        case .dockerRegistry: return registry(host: host, port: port ?? 443, why: why)
        case .logstashBeats: return logstash(why: why)
        case .elasticsearch: return elasticsearch(why: why)
        default: return nil
        }
    }
    public static func guidance(for f: Finding, target: Target?) -> [Guidance] {
        let host = target?.verifyName ?? AppConfig.current.hostPlaceholder
        switch f.kind {
        case "registry-cert", "registry-api": return [registry(host: host, port: target?.port ?? 443)]
        case "beats-tls": return [logstash(), filebeat()]
        case "es-cert": return [elasticsearch(), filebeat(output: "elasticsearch")]
        case "ca-chain": return f.severity >= .warning ? [filebeat(output: target?.service == .elasticsearch ? "elasticsearch" : "logstash")] : []
        case "mtls-client", "mtls-key", "mtls-ca": return f.severity >= .warning || f.kind == "mtls-client" && f.id == "mtls-required" ? [filebeat(), logstash()] : []
        default: return []
        }
    }
}

/// Form state of the app's Registry & Beats pane, kept in Core so it can be unit tested.
public struct StackForm: Equatable {
    public var host = "", service: Service = .dockerRegistry, port = "443", expected = "", checkV2 = false
    public init() {}
    public mutating func select(_ s: Service) { service = s; port = String(s.defaultPort); if s != .dockerRegistry { checkV2 = false } }
    public var canRun: Bool { !host.trimmingCharacters(in: .whitespaces).isEmpty }
    public var runsV2: Bool { checkV2 && service == .dockerRegistry }
    public var target: Target {
        let h = host.trimmingCharacters(in: .whitespaces)
        return Target(name: h, host: h, port: Int(port.trimmingCharacters(in: .whitespaces)) ?? -1, service: service,
                      expectedName: expected.trimmingCharacters(in: .whitespaces), platform: service.defaultPlatform ?? .generic)
    }
}
