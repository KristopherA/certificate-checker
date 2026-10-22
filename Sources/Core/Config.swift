import Foundation

/// User configuration. Nothing organisation-specific is compiled in; defaults are generic and KB links are empty
/// (KB buttons are hidden when a topic has no link).
/// Location: --config PATH (CLI), else $CERTCHECK_CONFIG ("none" = built-in defaults), else
/// ~/Library/Application Support/CertificateChecker/config.json, else defaults.
public struct AppConfig: Codable, Equatable {
    public var organizationName = ""
    /// Base folder for relative KB paths ("~" is expanded).
    public var kbRoot: String?
    /// KB topic key (see `KB`) → path relative to kbRoot, absolute/"~" path, or http(s)/file URL.
    public var kbLinks: [String: String] = [:]
    public var defaultDomain = "example.com"
    public var hostPlaceholder = "host.example.com"
    public var vpnHostPlaceholder = "vpn.example.com"
    public var radiusHostPlaceholder = "radius.example.com"
    public var signingProcedureDoc = "SIGNING-PROCEDURE.md"
    /// Optional path to the Connection Workbench app for the HTTPS hand-off (found by bundle ID otherwise).
    public var connectionWorkbenchApp: String?

    public init() {}
    enum CodingKeys: String, CodingKey { case organizationName, kbRoot, kbLinks, defaultDomain, hostPlaceholder, vpnHostPlaceholder, radiusHostPlaceholder, signingProcedureDoc, connectionWorkbenchApp }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self); let z = AppConfig()
        organizationName = try c.decodeIfPresent(String.self, forKey: .organizationName) ?? z.organizationName
        kbRoot = try c.decodeIfPresent(String.self, forKey: .kbRoot)
        kbLinks = try c.decodeIfPresent([String: String].self, forKey: .kbLinks) ?? [:]
        defaultDomain = try c.decodeIfPresent(String.self, forKey: .defaultDomain) ?? z.defaultDomain
        hostPlaceholder = try c.decodeIfPresent(String.self, forKey: .hostPlaceholder) ?? z.hostPlaceholder
        vpnHostPlaceholder = try c.decodeIfPresent(String.self, forKey: .vpnHostPlaceholder) ?? z.vpnHostPlaceholder
        radiusHostPlaceholder = try c.decodeIfPresent(String.self, forKey: .radiusHostPlaceholder) ?? z.radiusHostPlaceholder
        signingProcedureDoc = try c.decodeIfPresent(String.self, forKey: .signingProcedureDoc) ?? z.signingProcedureDoc
        connectionWorkbenchApp = try c.decodeIfPresent(String.self, forKey: .connectionWorkbenchApp)
    }

    public static var defaultURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CertificateChecker", isDirectory: true).appendingPathComponent("config.json")
    }
    /// Where the active configuration came from, for display ("built-in defaults" when none).
    public private(set) static var source = "built-in defaults"
    public private(set) static var loadError: String?
    public static var current: AppConfig = load(path: nil)

    @discardableResult
    public static func load(path: String?) -> AppConfig {
        loadError = nil
        let env = ProcessInfo.processInfo.environment["CERTCHECK_CONFIG"]
        if (path ?? env) == "none" { source = "built-in defaults"; return AppConfig() }
        let url = path.map { URL(fileURLWithPath: expand($0)) } ?? env.map { URL(fileURLWithPath: expand($0)) } ?? defaultURL
        guard FileManager.default.fileExists(atPath: url.path) else {
            if path != nil || env != nil { loadError = "Config file not found: \(url.path)" }
            source = "built-in defaults"; return AppConfig()
        }
        do {
            let data = try Data(contentsOf: url)
            guard data.count <= 1_000_000 else { throw CheckError.message("Config file is larger than 1 MB.") }
            let c = try JSONDecoder().decode(AppConfig.self, from: data)
            source = url.path; return c
        } catch { loadError = "Config file \(url.path) could not be read: \(error.localizedDescription)"; source = "built-in defaults"; return AppConfig() }
    }
    public static func use(path: String?) { current = load(path: path) }
    static func expand(_ p: String) -> String { (p as NSString).expandingTildeInPath }
}

/// KB topic keys. Links come only from the user config (`kbLinks`).
public enum KB {
    public static let pki = "pki", runbook = "runbook", checklist = "checklist", ldapsReplace = "ldapsReplace", ldapRef = "ldapRef"
    public static let mysqlRotation = "mysqlRotation", mysqlAdmin = "mysqlAdmin", zimbra = "zimbra", reverseProxy = "reverseProxy"
    public static let proxmox = "proxmox", synology = "synology", pfSense = "pfSense"
    public static let radiusGuide = "radiusGuide", radiusWifi = "radiusWifi", radius8021xAD = "radius8021x"
    public static let wgRunbook = "wgRunbook", wgCheatSheet = "wgCheatSheet", wgHandbook = "wgHandbook"
    public static let ikev2Profile = "ikev2Profile"
    public static let rdp = "rdp", rdGateway = "rdGateway", winrm = "winrm"
    public static let allKeys = [pki, runbook, checklist, ldapsReplace, ldapRef, mysqlRotation, mysqlAdmin, zimbra, reverseProxy, proxmox, synology, pfSense, radiusGuide, radiusWifi, radius8021xAD, wgRunbook, wgCheatSheet, wgHandbook, ikev2Profile, rdp, rdGateway, winrm]

    /// Resolved link for a topic key, or nil when the config has none.
    /// Bundles and scripts that macOS would run or install when "opened": never used as KB links.
    public static let refusedExtensions: Set<String> = ["app", "command", "terminal", "workflow", "tool", "sh", "pkg", "mpkg", "mobileconfig", "scpt", "applescript", "action", "prefpane", "kext",
        "fileloc", "webloc", "inetloc", "jar", "dmg", "url", "osax", "plugin", "bundle", "service", "shortcut", "saver", "qlgenerator", "mdimporter"]
    /// Resolves a topic link. Remote links must be https; local links must be regular, non-executable documents.
    public static func resolve(_ key: String, config: AppConfig = AppConfig.current) -> (url: URL?, problem: String?) {
        guard let v = config.kbLinks[key]?.trimmingCharacters(in: .whitespaces), !v.isEmpty else { return (nil, nil) }
        var u: URL
        if let p = URL(string: v), let s = p.scheme?.lowercased(), s.count > 1 {
            if s == "https" { return p.host?.isEmpty == false ? (p, nil) : (nil, "https link without a host") }
            guard s == "file" else { return (nil, "only https links are allowed for remote documents (got \(s):)") }
            u = p
        } else {
            let expanded = AppConfig.expand(v)
            if expanded.hasPrefix("/") { u = URL(fileURLWithPath: expanded) }
            else {
                guard let root = config.kbRoot, !root.isEmpty else { return (nil, "relative path needs kbRoot") }
                u = URL(fileURLWithPath: AppConfig.expand(root)).appendingPathComponent(v)
            }
        }
        // Check what the link really points to: a harmless-looking name can be a symlink to a bundle or script.
        let standardized = u.standardizedFileURL
        u = standardized.resolvingSymlinksInPath()
        // A broken symlink cannot be resolved, so resolvingSymlinksInPath() returns the link's own path and the
        // checks below use the link's own name. That is harmless: the target does not exist, nothing can be opened,
        // and a refused extension on the link name (e.g. x.app) is still refused. Covered by the broken-symlink tests.
        if refusedExtensions.contains(u.pathExtension.lowercased()) { return (nil, "refused: .\(u.pathExtension) would run or install something") }
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: u.path, isDirectory: &isDir) {
            if isDir.boolValue { return (nil, "refused: a folder or bundle, not a document") }
            if FileManager.default.isExecutableFile(atPath: u.path) { return (nil, "refused: the file is executable") }
        }
        return (u, nil)
    }
    public static func url(_ key: String, config: AppConfig = AppConfig.current) -> URL? { resolve(key, config: config).url }
    public static func label(_ key: String, config: AppConfig = AppConfig.current) -> String {
        guard let u = url(key, config: config) else { return key }
        return u.isFileURL ? u.lastPathComponent : (u.host ?? u.absoluteString)
    }
    /// Only the docs that have a configured link, in order.
    public static func available(_ keys: [String], config: AppConfig = AppConfig.current) -> [String] { keys.filter { url($0, config: config) != nil } }
}
