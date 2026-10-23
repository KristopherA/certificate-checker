import Foundation
import Security

// MARK: Code-signing certificates on apps, binaries and installer packages (0.9.0). Read-only and offline:
// Security.framework for code (no network revocation check), pkgutil --check-signature for .pkg. Guidance is copy-only.
public enum CodeSign {
    public struct Info {
        public var signed = false, adHoc = false, valid = false, hardenedRuntime = false
        public var validityError: String?
        public var identifier: String?, teamID: String?
        public var timestamp: Date?
        public var chain: [Certificate] = []
        public var pkgStatus: String?
        /// Installer packages: certificate names, expiry and SHA-256 from pkgutil's text (no DER is available).
        public var pkgChain: [PkgCert] = []
        public var notarized: Bool?
    }
    public struct PkgCert: Equatable { public var name: String; public var expires: Date?; public var sha256: String }

    public static func info(_ u: URL) throws -> Info {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: u.path, isDirectory: &isDir) else { throw CheckError.message("\(u.path) does not exist.") }
        if !isDir.boolValue, u.pathExtension.lowercased() == "pkg" { return try pkg(u) }
        var out = Info()
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(u as CFURL, [], &code) == errSecSuccess, let code else { throw CheckError.message("\(u.lastPathComponent) is not code macOS can read a signature from.") }
        var dict: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &dict) == errSecSuccess, let d = dict as? [String: Any] else { return out }
        out.identifier = d[kSecCodeInfoIdentifier as String] as? String
        out.signed = out.identifier != nil
        out.teamID = d[kSecCodeInfoTeamIdentifier as String] as? String
        out.timestamp = d[kSecCodeInfoTimestamp as String] as? Date
        let flags = (d[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        out.adHoc = flags & 0x2 != 0; out.hardenedRuntime = flags & 0x10000 != 0
        let certs = (d[kSecCodeInfoCertificates as String] as? [SecCertificate]) ?? []
        out.chain = certs.compactMap { try? Certificate(der: [UInt8](SecCertificateCopyData($0) as Data)) }
        if out.signed {
            var err: Unmanaged<CFError>?
            let st = SecStaticCodeCheckValidityWithErrors(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode | (1 << 29) /* kSecCSNoNetworkAccess (CSCommon.h); not imported into Swift */), nil, &err)
            out.valid = st == errSecSuccess
            if !out.valid { out.validityError = (err?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? "OSStatus \(st)" }
        }
        return out
    }

    /// pkgutil --check-signature (read-only). Its text output is parsed; certificate details beyond names and expiry are not available.
    /// The package name pkgutil sees, and expects in its `Package "…":` header.
    static let pkgLinkName = "package.pkg"
    static func pkg(_ u: URL) throws -> Info {
        // pkgutil echoes the path verbatim, so a crafted file name could inject lines. Run it on a fixed-name symlink
        // in a private (0700) temporary folder, so nothing it prints comes from the real name.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cc-pkg-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let link = dir.appendingPathComponent(pkgLinkName)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: u.standardizedFileURL)
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/sbin/pkgutil"); p.arguments = ["--check-signature", link.path]
        p.environment = ["LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        // stderr is discarded: it is not trusted and is not parsed.
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
        try p.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        let text = String(decoding: data.prefix(1_000_000), as: UTF8.self)
        var i = parsePkgutil(text)
        // pkgutil exits non-zero for unsigned or invalid packages; never report those as valid.
        if p.terminationStatus != 0 { i.valid = false; if i.validityError == nil { i.validityError = "pkgutil exited \(p.terminationStatus)" } }
        return i
    }
    static func parsePkgutil(_ text: String, expectedName: String = pkgLinkName) -> Info {
        var out = Info()
        let df = DateFormatter(); df.locale = Locale(identifier: "en_US_POSIX"); df.timeZone = TimeZone(identifier: "UTC"); df.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
        var inChain = false, inFP = false, inPackage = false, seen: Set<String> = []
        func spoofed(_ why: String) -> Info { var bad = Info(); bad.signed = true; bad.validityError = "Unexpected pkgutil output (\(why)); not trusted."; return bad }
        for line in text.split(separator: "\n", omittingEmptySubsequences: false).map({ $0.trimmingCharacters(in: .whitespaces) }) {
            // Only lines after the single expected header are read.
            if line.hasPrefix("Package \"") {
                guard !inPackage, line == "Package \"\(expectedName)\":" else { return spoofed("second or unexpected Package header") }
                inPackage = true; continue
            }
            guard inPackage else { continue }
            for key in ["Status:", "Notarization:", "Signed with a trusted timestamp on:", "Certificate Chain:"] where line.hasPrefix(key) {
                guard seen.insert(key).inserted else { return spoofed("\(key) appears twice") }
            }
            if line == "Certificate Chain:" { inChain = true; continue }
            if inChain {
                if let dot = line.firstIndex(of: "."), let n = Int(line[..<dot]), n == out.pkgChain.count + 1 {
                    out.pkgChain.append(PkgCert(name: String(line[line.index(after: dot)...]).trimmingCharacters(in: .whitespaces), expires: nil, sha256: "")); inFP = false; continue
                }
                guard !out.pkgChain.isEmpty else { continue }
                let last = out.pkgChain.count - 1
                if line.hasPrefix("Expires:") { out.pkgChain[last].expires = df.date(from: String(line.dropFirst(8)).trimmingCharacters(in: .whitespaces)); inFP = false; continue }
                if line == "SHA256 Fingerprint:" { inFP = true; continue }
                if inFP, !line.isEmpty, line.allSatisfy({ $0.isHexDigit || $0 == " " }) {
                    let hex = line.split(separator: " ").joined(separator: ":").uppercased()
                    out.pkgChain[last].sha256 += (out.pkgChain[last].sha256.isEmpty ? "" : ":") + hex; continue
                }
                inFP = false; continue
            }
            if line.hasPrefix("Notarization:") { out.notarized = line.lowercased().contains("trusted by the apple notary") }
            if line.hasPrefix("Status:") {
                let s = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces)
                out.pkgStatus = s; out.signed = !s.lowercased().contains("no signature"); let low = s.lowercased()
                out.valid = low.hasPrefix("signed") && !["expired", "untrusted", "invalid", "revoked", "not trusted"].contains { low.contains($0) }
                if !out.valid { out.validityError = s }
            }
            if line.hasPrefix("Signed with a trusted timestamp on:") {
                out.timestamp = df.date(from: String(line.dropFirst(35)).trimmingCharacters(in: .whitespaces))
            }
        }
        if let leaf = out.pkgChain.first?.name, let o = leaf.lastIndex(of: "("), let c = leaf.lastIndex(of: ")"), o < c {
            let team = String(leaf[leaf.index(after: o)..<c]); if team.count == 10, team.allSatisfy({ $0.isLetter || $0.isNumber }) { out.teamID = team }
        }
        return out
    }

    /// SHA-256 of "Apple Root CA" (System Roots keychain).
    static let appleRootCASHA256 = "B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24"
    public static func inspect(_ i: Info, now: Date = Clock.now(), warnDays: Int = 60) -> [Finding] {
        func f(_ id: String, _ s: Severity, _ t: Topic, _ title: String, _ d: String = "") -> Finding { Finding(id, s, t, title, d, kind: "codesign") }
        var out: [Finding] = []
        guard i.signed else { return [f("cs-signed", .fail, .general, "Not signed", "Gatekeeper blocks unsigned downloaded code.")] }
        if i.adHoc { out.append(f("cs-adhoc", .warning, .trust, "Ad-hoc signature (no certificate)", "Runs locally, but Gatekeeper rejects it after download and the identity changes on every build.")) }
        out.append(i.valid ? f("cs-valid", .pass, .trust, "Signature is valid") : f("cs-valid", .fail, .trust, "Signature is not valid", i.validityError ?? ""))
        if let t = i.teamID { out.append(f("cs-team", .info, .general, "Team ID \(t)")) }
        // Apple's own platform code is signed by "Software Signing" under Apple Root CA, without a timestamp or Hardened Runtime flag.
        let applePlatform = i.valid && i.pkgStatus == nil && i.chain.last?.sha256 == appleRootCASHA256 && (i.chain.first?.subject.commonName ?? "").hasSuffix("Software Signing")
        if applePlatform { out.append(f("cs-apple", .info, .general, "Apple platform code", "Timestamp and Hardened Runtime checks do not apply.")) }
        if i.pkgStatus == nil, !i.adHoc, !applePlatform { out.append(f("cs-runtime", i.hardenedRuntime ? .pass : .warning, .general, i.hardenedRuntime ? "Hardened Runtime on" : "Hardened Runtime off", i.hardenedRuntime ? "" : "Notarization requires the Hardened Runtime.")) }
        if let leaf = i.chain.first {
            let name = leaf.subject.commonName ?? leaf.subject.text
            if name.hasPrefix("Apple Development") || name.hasPrefix("Mac Developer") { out.append(f("cs-kind", .warning, .eku, "Development certificate: \(name)", "Use a Developer ID certificate for software given to other Macs.")) }
            else { out.append(f("cs-kind", .info, .eku, "Signed by \(name)")) }
            if let e = leaf.extendedKeyUsage, !e.contains(OID.codeSigning), !e.contains(OID.anyEKU) { out.append(f("cs-eku", .fail, .eku, "Leaf certificate lacks the Code Signing EKU")) }
            let days = Int(leaf.notAfter.timeIntervalSince(now) / 86_400)
            if days < 0 {
                if let ts = i.timestamp, ts <= leaf.notAfter { out.append(f("cs-expiry", .info, .expiry, "Certificate expired \(-days) days ago, signature timestamped", "The secure timestamp keeps the signature valid; re-sign with a current certificate for new builds.")) }
                else { out.append(f("cs-expiry", .fail, .expiry, "Certificate expired \(-days) days ago with no secure timestamp", "The signature is no longer trusted. Re-sign and re-notarize.")) }
            } else if days < warnDays { out.append(f("cs-expiry", .warning, .expiry, "Certificate expires in \(days) days", "Renew before releasing new builds.")) }
            else { out.append(f("cs-expiry", .pass, .expiry, "Certificate valid for \(days) more days")) }
            if case .rsa(let b) = leaf.publicKey.algorithm, b < 2048 { out.append(f("cs-key", .fail, .weakKey, "RSA key is \(b) bits")) }
            if i.chain.contains(where: { $0.signatureIsWeak && !$0.isSelfIssued }) { out.append(f("cs-sig", .fail, .weakSignature, "Weak signature algorithm in the chain")) }
        }
        if i.chain.isEmpty, let leaf = i.pkgChain.first {
            if leaf.name.hasPrefix("Developer ID Installer") || leaf.name.hasPrefix("3rd Party Mac Developer Installer") || leaf.name.hasPrefix("Mac Installer Distribution") { out.append(f("cs-kind", .info, .eku, "Signed by \(leaf.name)")) }
            else { out.append(f("cs-kind", .warning, .eku, "Signed by \(leaf.name)", "Packages given to other Macs should be signed with a Developer ID Installer certificate.")) }
            if let e = leaf.expires {
                let days = Int(e.timeIntervalSince(now) / 86_400)
                if days < 0 {
                    if let ts = i.timestamp, ts <= e { out.append(f("cs-expiry", .info, .expiry, "Certificate expired \(-days) days ago, signature timestamped", "The secure timestamp keeps the signature valid; re-sign with a current certificate for new builds.")) }
                    else { out.append(f("cs-expiry", .fail, .expiry, "Certificate expired \(-days) days ago with no secure timestamp", "The signature is no longer trusted. Re-sign the package.")) }
                } else if days < warnDays { out.append(f("cs-expiry", .warning, .expiry, "Certificate expires in \(days) days", "Renew before releasing new packages.")) }
                else { out.append(f("cs-expiry", .pass, .expiry, "Certificate valid for \(days) more days")) }
            }
        }
        if let n = i.notarized { out.append(f("cs-notarized", n ? .pass : .warning, .trust, n ? "Notarized by Apple" : "Not notarized", n ? "" : "Gatekeeper blocks un-notarized downloaded packages. Notarize with: xcrun notarytool submit PKG --wait")) }
        if !i.adHoc, !applePlatform, i.timestamp == nil { out.append(f("cs-timestamp", .warning, .general, "No secure timestamp", "The signature stops being trusted when the certificate expires.")) }
        return out
    }
}
