import Foundation

public enum Service: String, Codable, CaseIterable, Identifiable {
    case https = "HTTPS", tls = "TLS (implicit)", ldaps = "LDAPS", ldapStartTLS = "LDAP StartTLS"
    case smtpStartTLS = "SMTP STARTTLS", smtps = "SMTPS", imapStartTLS = "IMAP STARTTLS", imaps = "IMAPS"
    case pop3StartTLS = "POP3 STLS", pop3s = "POP3S", mysql = "MySQL TLS"
    case rdp = "RDP (TLS)", rdGateway = "RD Gateway (HTTPS)", winrmHTTPS = "WinRM HTTPS"
    case synologyDSM = "Synology DSM (HTTPS)", proxmoxVE = "Proxmox VE (HTTPS)", proxmoxBackup = "Proxmox Backup Server (HTTPS)"
    case dockerRegistry = "Docker registry (HTTPS)", logstashBeats = "Logstash Beats input (TLS)", elasticsearch = "Elasticsearch (HTTPS)"
    case munkiRepo = "Munki repo (HTTPS)", fileMaker = "FileMaker Server (TLS)", retrospectConsole = "Retrospect web console (HTTPS)"
    case hpPrinter = "HP printer EWS (HTTPS)", barracudaService = "Barracuda WAF service (HTTPS)", barracudaManagement = "Barracuda WAF management (HTTPS)"
    public var id: String { rawValue }
    public var defaultPort: Int {
        switch self {
        case .https, .tls: return 443
        case .ldaps: return 636
        case .ldapStartTLS: return 389
        case .smtpStartTLS: return 587
        case .smtps: return 465
        case .imapStartTLS: return 143
        case .imaps: return 993
        case .pop3StartTLS: return 110
        case .pop3s: return 995
        case .mysql: return 3306
        case .rdp: return 3389
        case .rdGateway: return 443
        case .winrmHTTPS: return 5986
        case .synologyDSM: return 5001
        case .proxmoxVE: return 8006
        case .proxmoxBackup: return 8007
        case .dockerRegistry: return 443   // the stock registry:2 image listens on 5000
        case .logstashBeats: return 5044
        case .elasticsearch: return 9200
        case .munkiRepo, .fileMaker, .retrospectConsole, .hpPrinter, .barracudaService: return 443   // FileMaker clients also use 5003; Retrospect Virtual can use 8443
        case .barracudaManagement: return 8443
        }
    }
    public var usesUpgrade: Bool { [.ldapStartTLS, .smtpStartTLS, .imapStartTLS, .pop3StartTLS, .mysql, .rdp].contains(self) }
    /// RDP, RD Gateway and WinRM: Windows remote administration services with their own certificate rules.
    public var isRemoteAdmin: Bool { [.rdp, .rdGateway, .winrmHTTPS].contains(self) }
    /// Services whose certificate can be checked against a SHA-256 fingerprint pin.
    public var acceptsFingerprintPin: Bool { self == .proxmoxBackup || self == .proxmoxVE }
    /// Synology DSM, Proxmox VE and Proxmox Backup Server web/API TLS endpoints.
    public var isAppliance: Bool { [.synologyDSM, .proxmoxVE, .proxmoxBackup].contains(self) }
    /// Docker registry, Logstash Beats input and Elasticsearch TLS endpoints (0.7.0).
    /// Munki, FileMaker Server, Retrospect, HP printer EWS and Barracuda WAF: one handshake, vendor default-certificate rules.
    public var isVendor: Bool { [.munkiRepo, .fileMaker, .retrospectConsole, .hpPrinter, .barracudaService, .barracudaManagement].contains(self) }
    public var isStack: Bool { [.dockerRegistry, .logstashBeats, .elasticsearch].contains(self) }
    /// Windows guidance platform for the remote-admin services.
    public var windowsPlatform: Platform? { switch self { case .rdp: return .windowsRDP; case .rdGateway: return .windowsRDGateway; case .winrmHTTPS: return .windowsWinRM; default: return nil } }
    /// Guidance platform to use when the target is left on Generic.
    public var defaultPlatform: Platform? { switch self { case .synologyDSM: return .synology; case .proxmoxVE: return .proxmoxVE; case .proxmoxBackup: return .proxmoxBackup; case .dockerRegistry: return .dockerRegistry; case .logstashBeats, .elasticsearch: return .elasticStack; case .munkiRepo: return .munki; case .fileMaker: return .fileMaker; case .retrospectConsole: return .retrospect; case .hpPrinter: return .hpPrinter; case .barracudaService, .barracudaManagement: return .barracuda; default: return windowsPlatform } }
    /// Equivalent copy-only openssl command for an admin to reproduce the probe.
    public var opensslStartTLS: String? {
        switch self {
        case .smtpStartTLS: return "smtp"; case .imapStartTLS: return "imap"; case .pop3StartTLS: return "pop3"
        case .ldapStartTLS: return "ldap"; case .mysql: return "mysql"; default: return nil
        }
    }
}

public enum Platform: String, Codable, CaseIterable, Identifiable {
    case generic = "Generic / unknown", pfSense = "pfSense", windowsAD = "Windows AD (LDAPS)", windowsIIS = "Windows IIS / RD Gateway"
    case nginx = "Linux nginx", apache = "Linux Apache", zimbra = "Zimbra mail", mysql = "MySQL", synology = "Synology DSM"
    case proxmoxVE = "Proxmox VE", proxmoxBackup = "Proxmox Backup Server", macOS = "macOS"
    case windowsRDP = "Windows RDP host", windowsRDGateway = "Windows RD Gateway", windowsWinRM = "Windows WinRM"
    case dockerRegistry = "Docker registry", elasticStack = "Elastic Stack (Beats / Logstash / Elasticsearch)"
    case munki = "Munki", fileMaker = "FileMaker Server", retrospect = "Retrospect", hpPrinter = "HP printer (EWS)", barracuda = "Barracuda WAF"
    public var id: String { rawValue }
}

public struct Target: Codable, Identifiable, Equatable, Hashable {
    public var id = UUID()
    public var name: String
    public var host: String
    public var port: Int
    public var service: Service
    /// SNI to send when it differs from the host (for example connecting by IP).
    public var sni: String = ""
    /// Name the certificate must cover. Defaults to SNI, then host.
    public var expectedName: String = ""
    public var platform: Platform = .generic
    public var notes: String = ""
    /// Proxmox Backup Server only: expected SHA-256 fingerprint (colon-hex). Optional so older targets.json files still decode.
    public var fingerprintPin: String?
    /// Optional numeric IP to connect to instead of resolving `host` (split DNS / hairpin NAT workaround).
    /// SNI and the expected certificate name stay the hostname. Optional so older targets.json files still decode.
    public var connectIP: String?

    public init(name: String, host: String, port: Int? = nil, service: Service, sni: String = "", expectedName: String = "", platform: Platform = .generic, notes: String = "") {
        self.name = name; self.host = host; self.port = port ?? service.defaultPort; self.service = service
        self.sni = sni; self.expectedName = expectedName; self.platform = platform; self.notes = notes
    }
    enum CodingKeys: String, CodingKey { case id, name, host, port, service, sni, expectedName, platform, notes, fingerprintPin, connectIP }
    /// Missing optional keys take their defaults (older or hand-written targets.json). Unknown service/platform values still fail the load.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        host = try c.decode(String.self, forKey: .host)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? host
        service = try c.decode(Service.self, forKey: .service)
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? service.defaultPort
        sni = try c.decodeIfPresent(String.self, forKey: .sni) ?? ""
        expectedName = try c.decodeIfPresent(String.self, forKey: .expectedName) ?? ""
        platform = try c.decodeIfPresent(Platform.self, forKey: .platform) ?? .generic
        notes = try c.decodeIfPresent(String.self, forKey: .notes) ?? ""
        fingerprintPin = try c.decodeIfPresent(String.self, forKey: .fingerprintPin)
        connectIP = try c.decodeIfPresent(String.self, forKey: .connectIP)
    }
    /// SNI and the expected name drop one trailing dot: RFC 6066 forbids it in server_name, and certificates never carry it.
    public var serverName: String { Target.withoutTrailingDot(sni.isEmpty ? host : sni) }
    public var verifyName: String { expectedName.isEmpty ? serverName : Target.withoutTrailingDot(expectedName) }
    static func withoutTrailingDot(_ s: String) -> String { s.hasSuffix(".") ? String(s.dropLast()) : s }
    /// The trimmed connect-IP override, or nil when none is set.
    public var connectOverride: String? { let s = connectIP?.trimmingCharacters(in: .whitespaces) ?? ""; return s.isEmpty ? nil : s }
    /// What the socket actually connects to: the override IP, else the host (resolved by the system resolver).
    public var connectHost: String { connectOverride ?? host }
    public var resolverSource: ResolverSource { connectOverride != nil ? .override : (Resolution.isIP(host) ? .literal : .system) }
    public var connectEndpoint: String { connectHost.contains(":") ? "[\(connectHost)]:\(port)" : "\(connectHost):\(port)" }
    public var endpoint: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    public static func validHost(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 253, s.contains(where: { $0 != "." }) else { return false }   // "." alone (the DNS root) is not a host
        return s.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) && $0.isASCII || "-.:_".unicodeScalars.contains($0) } && !s.hasPrefix("-")
    }
    public func validate() throws {
        guard Target.validHost(host) else { throw CheckError.message("Host must be a hostname or IP address (letters, digits, '.', '-', ':').") }
        guard (1...65535).contains(port) else { throw CheckError.message("Port must be 1–65535.") }
        for s in [sni, expectedName] where !s.isEmpty { guard Target.validHost(s) else { throw CheckError.message("SNI and expected name must be hostnames.") } }
        if let ip = connectOverride { guard Resolution.isIP(ip) else { throw CheckError.message("Connect IP must be a numeric IPv4 or IPv6 address.") } }
        if let p = fingerprintPin, !p.trimmingCharacters(in: .whitespaces).isEmpty {
            guard service.acceptsFingerprintPin else { throw CheckError.message("A fingerprint pin applies only to Proxmox Backup Server and Proxmox VE targets.") }
            guard FingerprintPin.normalize(p) != nil else { throw CheckError.message("Fingerprint pin must be a SHA-256 value in colon-hex form (AA:BB:…, 32 bytes).") }
        }
        guard name.count <= 120, notes.count <= 2000 else { throw CheckError.message("Name or notes are too long.") }
    }
}

/// Persists targets only (no results, keys or passwords) with 0600 permissions.
public struct TargetStore {
    public let url: URL
    public init(url: URL? = nil) {
        self.url = url ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CertificateChecker", isDirectory: true).appendingPathComponent("targets.json")
    }
    /// Refuses a symlinked parent folder. The file itself is opened with O_NOFOLLOW and its type is checked on the
    /// open descriptor, so a symlink swapped in after a check is never followed.
    func checkParent() throws {
        var st = stat(); let dir = url.deletingLastPathComponent().path
        if lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFLNK { throw CheckError.message("The folder holding \(url.lastPathComponent) is a symlink; refusing to use it.") }
    }
    /// The current file's bytes, or nil when there is none. Anything that is not a regular file is refused.
    func readRegular() throws -> Data? {
        try checkParent()
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw CheckError.message("\(url.lastPathComponent) is not a regular file (symlink or other type); refusing to read or write it.")
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { throw CheckError.message("\(url.lastPathComponent) is not a regular file; refusing to read or write it.") }
        guard st.st_size <= 2_000_000 else { throw CheckError.message("\(url.lastPathComponent) is larger than 2 MB.") }
        return try FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() ?? Data()
    }
    public func load() throws -> [Target] {
        guard let d = try readRegular() else { return [] }
        return try JSONDecoder().decode([Target].self, from: d)
    }
    /// Writes the current bytes to targets.json.bak-<timestamp>[-NNN] (0600, never overwriting) and returns it; nil when there is no file.
    @discardableResult public func backup(now: Date = Clock.now()) throws -> URL? {
        guard let data = try readRegular() else { return nil }
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyyMMdd-HHmmss"
        let base = url.lastPathComponent + ".bak-" + f.string(from: now), dir = url.deletingLastPathComponent()
        var dest = dir.appendingPathComponent(base), n = 1
        while FileManager.default.fileExists(atPath: dest.path) || (try? FileManager.default.destinationOfSymbolicLink(atPath: dest.path)) != nil {
            n += 1; dest = dir.appendingPathComponent(base + String(format: "-%03d", n))
        }
        let fd = open(dest.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw CheckError.message("Could not create backup \(dest.lastPathComponent).") }
        let h = FileHandle(fileDescriptor: fd, closeOnDealloc: true); try h.write(contentsOf: data); try h.close()
        return dest
    }
    public func save(_ targets: [Target]) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        _ = try readRegular()
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        // Write a 0600 temp file (never following links, never reusing a name) and rename it over targets.json,
        // so the file never exists with umask permissions.
        let data = try enc.encode(targets)
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).tmp-\(UUID().uuidString)")
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw CheckError.message("Could not create a temporary file next to \(url.lastPathComponent).") }
        do {
            let h = FileHandle(fileDescriptor: fd, closeOnDealloc: true); try h.write(contentsOf: data); try h.synchronize(); try h.close()
            guard rename(tmp.path, url.path) == 0 else { throw CheckError.message("Could not replace \(url.lastPathComponent).") }
        } catch { unlink(tmp.path); throw error }
    }
}

/// Load-then-save guard: when targets.json cannot be decoded, the file is backed up and every save is refused,
/// so an unreadable file is never replaced by an empty list.
public struct TargetLibrary {
    public let store: TargetStore
    public private(set) var targets: [Target] = []
    public private(set) var loadError: String?
    public private(set) var backupURL: URL?
    public var savesBlocked: Bool { loadError != nil }
    public init(store: TargetStore = TargetStore()) {
        self.store = store
        do { targets = try store.load() } catch {
            loadError = "Saved targets could not be read (\(error.localizedDescription)). Saving is disabled so the file is not overwritten."
            backupURL = try? store.backup()
            if let b = backupURL { loadError! += " A copy was saved as \(b.lastPathComponent)." }
        }
    }
    public mutating func save(_ list: [Target]) throws {
        if let e = loadError { throw CheckError.message(e + " Fix or remove \(store.url.lastPathComponent), then reopen Certificate Checker.") }
        try store.backup()
        try store.save(list); targets = list
        Self.pruneBackups(store)
    }
    /// Validates, saves, and only then updates `targets`. On any error `targets` is unchanged.
    public mutating func upsert(_ t: Target) throws {
        try t.validate()
        var next = targets
        if let i = next.firstIndex(where: { $0.id == t.id }) { next[i] = t } else { next.append(t) }
        try save(next)
    }
    /// Saves without the target, then updates `targets`. On any error `targets` is unchanged.
    public mutating func delete(id: UUID) throws { try save(targets.filter { $0.id != id }) }
    /// Keeps the 5 newest backups.
    static func pruneBackups(_ store: TargetStore) {
        let dir = store.url.deletingLastPathComponent(), prefix = store.url.lastPathComponent + ".bak-"
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else { return }
        let baks = names.filter { n in
            var st = stat()
            return n.hasPrefix(prefix) && lstat(dir.appendingPathComponent(n).path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG
        }.sorted()
        // unlink never removes a directory and removes a symlink itself, not its target.
        for n in baks.dropLast(5) { _ = unlink(dir.appendingPathComponent(n).path) }
    }
}
