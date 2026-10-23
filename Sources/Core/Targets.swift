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

    public init(name: String, host: String, port: Int? = nil, service: Service, sni: String = "", expectedName: String = "", platform: Platform = .generic, notes: String = "") {
        self.name = name; self.host = host; self.port = port ?? service.defaultPort; self.service = service
        self.sni = sni; self.expectedName = expectedName; self.platform = platform; self.notes = notes
    }
    enum CodingKeys: String, CodingKey { case id, name, host, port, service, sni, expectedName, platform, notes, fingerprintPin }
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
    }
    public var serverName: String { sni.isEmpty ? host : sni }
    public var verifyName: String { expectedName.isEmpty ? serverName : expectedName }
    public var endpoint: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    public static func validHost(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 253 else { return false }
        return s.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) && $0.isASCII || "-.:_".unicodeScalars.contains($0) } && !s.hasPrefix("-")
    }
    public func validate() throws {
        guard Target.validHost(host) else { throw CheckError.message("Host must be a hostname or IP address (letters, digits, '.', '-', ':').") }
        guard (1...65535).contains(port) else { throw CheckError.message("Port must be 1–65535.") }
        for s in [sni, expectedName] where !s.isEmpty { guard Target.validHost(s) else { throw CheckError.message("SNI and expected name must be hostnames.") } }
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
    /// Refuses anything at the targets path that is not a regular file (symlinks included).
    func requireRegularFile() throws -> Bool {
        guard let a = try? FileManager.default.attributesOfItem(atPath: url.path) else { return false }
        guard (a[.type] as? FileAttributeType) == .typeRegular else { throw CheckError.message("\(url.lastPathComponent) is not a regular file (symlink or other type); refusing to read or write it.") }
        return true
    }
    public func load() throws -> [Target] {
        guard try requireRegularFile() else { return [] }
        return try JSONDecoder().decode([Target].self, from: Data(contentsOf: url))
    }
    /// Copies the current file to targets.json.bak-<timestamp> (0600) and returns the copy; nil when there is no file.
    @discardableResult public func backup(now: Date = Date()) throws -> URL? {
        guard try requireRegularFile() else { return nil }
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyyMMdd-HHmmss"
        var dest = url.deletingLastPathComponent().appendingPathComponent(url.lastPathComponent + ".bak-" + f.string(from: now)), n = 1
        while FileManager.default.fileExists(atPath: dest.path) { n += 1; dest = url.deletingLastPathComponent().appendingPathComponent(url.lastPathComponent + ".bak-" + f.string(from: now) + "-\(n)") }
        try FileManager.default.copyItem(at: url, to: dest)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: dest.path)
        return dest
    }
    public func save(_ targets: [Target]) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        _ = try requireRegularFile()
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode(targets).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
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
    /// Keeps the 5 newest backups.
    static func pruneBackups(_ store: TargetStore) {
        let dir = store.url.deletingLastPathComponent(), prefix = store.url.lastPathComponent + ".bak-"
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else { return }
        let baks = names.filter { n in
            guard n.hasPrefix(prefix), let a = try? FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent(n).path) else { return false }
            return (a[.type] as? FileAttributeType) == .typeRegular
        }.sorted()
        for n in baks.dropLast(5) { try? FileManager.default.removeItem(at: dir.appendingPathComponent(n)) }
    }
}
