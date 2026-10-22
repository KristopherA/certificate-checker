import Foundation

public enum Service: String, Codable, CaseIterable, Identifiable {
    case https = "HTTPS", tls = "TLS (implicit)", ldaps = "LDAPS", ldapStartTLS = "LDAP StartTLS"
    case smtpStartTLS = "SMTP STARTTLS", smtps = "SMTPS", imapStartTLS = "IMAP STARTTLS", imaps = "IMAPS"
    case pop3StartTLS = "POP3 STLS", pop3s = "POP3S", mysql = "MySQL TLS"
    case rdp = "RDP (TLS)", rdGateway = "RD Gateway (HTTPS)", winrmHTTPS = "WinRM HTTPS"
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
        }
    }
    public var usesUpgrade: Bool { [.ldapStartTLS, .smtpStartTLS, .imapStartTLS, .pop3StartTLS, .mysql, .rdp].contains(self) }
    /// RDP, RD Gateway and WinRM: Windows remote administration services with their own certificate rules.
    public var isRemoteAdmin: Bool { [.rdp, .rdGateway, .winrmHTTPS].contains(self) }
    /// Guidance platform to use when the target is left on Generic.
    public var windowsPlatform: Platform? { switch self { case .rdp: return .windowsRDP; case .rdGateway: return .windowsRDGateway; case .winrmHTTPS: return .windowsWinRM; default: return nil } }
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

    public init(name: String, host: String, port: Int? = nil, service: Service, sni: String = "", expectedName: String = "", platform: Platform = .generic, notes: String = "") {
        self.name = name; self.host = host; self.port = port ?? service.defaultPort; self.service = service
        self.sni = sni; self.expectedName = expectedName; self.platform = platform; self.notes = notes
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
    public func load() throws -> [Target] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        return try JSONDecoder().decode([Target].self, from: Data(contentsOf: url))
    }
    public func save(_ targets: [Target]) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode(targets).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
