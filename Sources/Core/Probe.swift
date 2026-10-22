import Foundation
import Security

public struct ProbeResult: Identifiable {
    public let id = UUID()
    public var target: Target
    public var started = Date()
    public var duration: TimeInterval = 0
    public var tlsVersion: String?
    public var chain: [Certificate] = []
    public var findings: [Finding] = []
    public var transcript: [String] = []
    public var error: String?
    /// Findings from the plaintext negotiation stage (RDP X.224), kept even when TLS is not reached.
    public var negotiation: [Finding] = []
    public var worst: Severity { findings.map(\.severity).max() ?? .info }
}

/// Builders and parsers for the plaintext stage of each protocol. Pure functions so they can be unit tested.
public enum Wire {
    public static let ldapStartTLSOID = "1.3.6.1.4.1.1466.20037"
    /// LDAPv3 ExtendedRequest for StartTLS (RFC 4511 §4.14.1), messageID 1.
    public static func ldapStartTLSRequest() -> [UInt8] {
        let oid = Array(ldapStartTLSOID.utf8)
        let ext = DER.tlv(0x77, DER.tlv(0x80, oid))
        return DER.tlv(0x30, [0x02, 0x01, 0x01] + ext)
    }
    /// Returns the LDAP resultCode of an ExtendedResponse, or nil if it is not one.
    public static func ldapExtendedResultCode(_ message: [UInt8]) -> Int? {
        guard let parts = try? DER.parse(message).children(), parts.count >= 2, let op = parts.first(where: { $0.tag == 0x78 }),
              let code = try? op.children().first, code.tag == 0x0A else { return nil }
        return code.intValue
    }
    public struct MySQLGreeting: Equatable { public let version: String; public let supportsTLS: Bool }
    public static func parseMySQLGreeting(_ payload: [UInt8]) throws -> MySQLGreeting {
        guard let proto = payload.first else { throw CheckError.message("Empty MySQL greeting") }
        if proto == 0xFF {
            let msg = payload.count > 3 ? String(decoding: payload.dropFirst(3), as: UTF8.self) : ""
            throw CheckError.message("MySQL refused the connection: \(msg.prefix(200))")
        }
        guard proto == 10, let nul = payload.dropFirst().firstIndex(of: 0) else { throw CheckError.message("Unsupported MySQL protocol \(proto)") }
        let version = String(decoding: payload[1..<nul], as: UTF8.self)
        let capIndex = nul + 1 + 4 + 8 + 1
        guard payload.count >= capIndex + 2 else { throw CheckError.message("Truncated MySQL greeting") }
        let caps = UInt16(payload[capIndex]) | UInt16(payload[capIndex + 1]) << 8
        return MySQLGreeting(version: version, supportsTLS: caps & 0x0800 != 0)
    }
    /// MySQL SSLRequest packet (sequence 1): CLIENT_SSL | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION.
    public static func mysqlSSLRequest() -> [UInt8] {
        let caps: UInt32 = 0x0800 | 0x0200 | 0x8000
        var p: [UInt8] = withUnsafeBytes(of: caps.littleEndian) { Array($0) }
        p += withUnsafeBytes(of: UInt32(16 * 1024 * 1024).littleEndian) { Array($0) }
        p.append(0x21)
        p += [UInt8](repeating: 0, count: 23)
        return [UInt8(p.count & 0xFF), UInt8((p.count >> 8) & 0xFF), UInt8((p.count >> 16) & 0xFF), 1] + p
    }
    /// Parses an SMTP multi-line reply. Returns nil until the final line ("250 ...") has arrived.
    public static func smtpReply(_ lines: [String]) -> (code: Int, lines: [String])? {
        guard let last = lines.last, last.count >= 3, let code = Int(last.prefix(3)) else { return nil }
        guard lines.allSatisfy({ $0.hasPrefix(String(last.prefix(3))) }) else { return (-1, lines) }
        if last.count == 3 || last[last.index(last.startIndex, offsetBy: 3)] == " " { return (code, lines) }
        return nil
    }
    public static func sanitize(_ s: String) -> String {
        String(s.unicodeScalars.filter { $0.value >= 0x20 && $0.value < 0x7F }.prefix(200).map(Character.init))
    }
}

/// Synchronous stream connection driven on a private run loop. Must be used on one dedicated thread.
final class StreamConnection {
    let input: InputStream, output: OutputStream
    var buffer: [UInt8] = []
    let deadline: Date
    init(host: String, port: Int, timeout: TimeInterval) throws {
        var i: InputStream?, o: OutputStream?
        Stream.getStreamsToHost(withName: host, port: port, inputStream: &i, outputStream: &o)
        guard let i, let o else { throw CheckError.message("Could not create a connection to \(host).") }
        input = i; output = o; deadline = Date().addingTimeInterval(timeout)
    }
    func setTLS(peerName: String) {
        // Chain validation is deliberately OFF here so the handshake completes and the chain can be inspected;
        // Trust.evaluate performs the real evaluation (with hostname policy) afterwards and reports the result.
        let settings: [String: Any] = [kCFStreamSSLPeerName as String: peerName, kCFStreamSSLValidatesCertificateChain as String: false]
        input.setProperty(settings, forKey: Stream.PropertyKey(kCFStreamPropertySSLSettings as String))
        output.setProperty(settings, forKey: Stream.PropertyKey(kCFStreamPropertySSLSettings as String))
    }
    func open() throws {
        input.schedule(in: .current, forMode: .default); output.schedule(in: .current, forMode: .default)
        input.open(); output.open()
        try pump { self.output.streamStatus == .open && self.input.streamStatus == .open }
    }
    func close() {
        input.close(); output.close()
        input.remove(from: .current, forMode: .default); output.remove(from: .current, forMode: .default)
    }
    func checkError() throws {
        for s in [input as Stream, output as Stream] where s.streamStatus == .error {
            throw CheckError.message(s.streamError?.localizedDescription ?? "Connection error")
        }
    }
    func pump(_ done: () -> Bool) throws {
        while true {
            if input.hasBytesAvailable {
                var chunk = [UInt8](repeating: 0, count: 16_384)
                let n = input.read(&chunk, maxLength: chunk.count)
                if n > 0 { buffer += chunk[0..<n]; guard buffer.count < 1_000_000 else { throw CheckError.message("Server sent too much data.") } }
            }
            if done() { return }
            try checkError()
            if input.streamStatus == .atEnd { throw CheckError.message("Server closed the connection.") }
            guard Date() < deadline else { throw CheckError.message("Timed out.") }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.02))
        }
    }
    func write(_ bytes: [UInt8]) throws {
        var sent = 0
        while sent < bytes.count {
            try pump { self.output.hasSpaceAvailable }
            let n = bytes[sent...].withUnsafeBufferPointer { output.write($0.baseAddress!, maxLength: $0.count) }
            if n < 0 { try checkError(); throw CheckError.message("Write failed.") }
            sent += n
        }
    }
    func write(_ s: String) throws { try write(Array(s.utf8)) }
    func readLine() throws -> String {
        try pump { buffer.contains(0x0A) }
        let i = buffer.firstIndex(of: 0x0A)!
        let line = String(decoding: buffer[..<i], as: UTF8.self).trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
        buffer.removeFirst(i + 1)
        return line
    }
    func read(_ n: Int) throws -> [UInt8] {
        try pump { buffer.count >= n }
        let out = Array(buffer[..<n]); buffer.removeFirst(n); return out
    }
    func peerTrust() -> SecTrust? {
        guard let v = input.property(forKey: Stream.PropertyKey(kCFStreamPropertySSLPeerTrust as String)) else { return nil }
        let cf = v as CFTypeRef
        guard CFGetTypeID(cf) == SecTrustGetTypeID() else { return nil }
        return (cf as! SecTrust) // type verified above
    }
}

public enum Probe {
    public static var timeout: TimeInterval = 15

    /// Runs on a dedicated thread with its own run loop. Never follows redirects, sends no credentials, reads no application data.
    /// Whether SecTrust may fetch intermediates (AIA) or revocation data. Off for appliance checks (one handshake, no other traffic).
    public static func allowsTrustNetworkFetch(_ s: Service) -> Bool { !s.isAppliance }
    public static func run(_ target: Target, timeout: TimeInterval = Probe.timeout) async -> ProbeResult {
        await withCheckedContinuation { c in
            let t = Thread { c.resume(returning: runSync(target, timeout: timeout)) }
            t.stackSize = 1 << 20; t.start()
        }
    }

    public static func runSync(_ target: Target, timeout: TimeInterval = Probe.timeout) -> ProbeResult {
        var r = ProbeResult(target: target)
        let start = Date()
        do {
            try target.validate()
            let conn = try StreamConnection(host: target.host, port: target.port, timeout: timeout)
            defer { conn.close() }
            if !target.service.usesUpgrade { conn.setTLS(peerName: target.serverName) }
            try conn.open()
            r.transcript.append("Connected to \(target.endpoint)")
            if target.service.usesUpgrade {
                try upgrade(conn, target, &r)
                // CVE-2011-0411 class: any plaintext buffered after the "go ahead" reply would be treated as protected data.
                guard conn.buffer.isEmpty else { throw ProbeError(text: "Server sent \(conn.buffer.count) unexpected bytes before the TLS handshake (possible STARTTLS injection).") }
                conn.setTLS(peerName: target.serverName)
            }
            try conn.pump { conn.peerTrust() != nil }
            r.transcript.append("TLS handshake complete (SNI \(target.serverName))")
            guard let trust = conn.peerTrust() else { throw CheckError.message("No certificate received.") }
            r.chain = presented(trust)
            r.tlsVersion = negotiatedVersion(conn)
            r.duration = Date().timeIntervalSince(start)
            var f = Analysis.evaluate(certificates: r.chain, hostname: target.verifyName, purpose: .tlsServer)
            // Presented order matters for servers: re-flag if the server sent certificates out of order.
            f.append(Trust.finding(Trust.evaluate(r.chain, hostname: target.verifyName, purpose: .tlsServer, allowNetwork: allowsTrustNetworkFetch(target.service)), context: "as presented by server"))
            // Appliance checks never let trust evaluation fetch intermediates (AIA) or check revocation online: one handshake, no other traffic.
            if r.tlsVersion == nil { f.append(Finding("tlsver", .info, .general, "TLS version not determined", "macOS did not report the negotiated protocol for this connection.")) }
            if let v = r.tlsVersion, v == "TLS 1.0" || v == "TLS 1.1" { f.append(Finding("tlsver", .warning, .general, "Server negotiated \(v)", "Disable TLS 1.0/1.1 on the service.")) }
            f = Remote.adjust(f, chain: r.chain, target: target)
            f = Appliance.adjust(f, chain: r.chain, target: target)
            r.findings = (r.negotiation + f).sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity }
        } catch {
            r.duration = Date().timeIntervalSince(start)
            r.error = error.localizedDescription
            let topic: Topic = (error as? ProbeError) != nil ? .startTLS : .connection
            let probe = Finding("probe", .fail, topic, topic == .startTLS ? "TLS upgrade failed" : "Could not complete TLS to \(target.endpoint)", error.localizedDescription)
            // A failed RDP negotiation already explains itself; do not repeat it as a generic upgrade failure.
            r.findings = r.negotiation.contains { $0.severity == .fail } ? r.negotiation : r.negotiation + [probe]
        }
        return r
    }

    struct ProbeError: Error, LocalizedError { let text: String; var errorDescription: String? { text } }

    static func upgrade(_ c: StreamConnection, _ t: Target, _ r: inout ProbeResult) throws {
        func log(_ dir: String, _ s: String) { r.transcript.append("\(dir) \(Wire.sanitize(s))") }
        func smtpRead() throws -> (Int, [String]) {
            var lines: [String] = []
            while true { let l = try c.readLine(); log("S:", l); lines.append(l); if let rep = Wire.smtpReply(lines) { return (rep.code, rep.lines) }; if lines.count > 100 { throw ProbeError(text: "SMTP reply too long") } }
        }
        switch t.service {
        case .smtpStartTLS:
            let (banner, _) = try smtpRead()
            guard banner != -1 else { throw ProbeError(text: "SMTP greeting is malformed: its continuation lines carry different reply codes.") }
            guard banner == 220 else { throw ProbeError(text: "SMTP banner was \(banner), expected 220.") }
            try c.write("EHLO certificate-checker.invalid\r\n"); log("C:", "EHLO certificate-checker.invalid")
            let (code, lines) = try smtpRead()
            guard code != -1 else { throw ProbeError(text: "EHLO reply is malformed: its continuation lines carry different reply codes.") }
            guard code == 250 else { throw ProbeError(text: "EHLO returned \(code).") }
            guard lines.contains(where: { $0.uppercased().dropFirst(4).hasPrefix("STARTTLS") }) else { throw ProbeError(text: "Server does not advertise STARTTLS.") }
            try c.write("STARTTLS\r\n"); log("C:", "STARTTLS")
            let (st, _) = try smtpRead()
            guard st != -1 else { throw ProbeError(text: "STARTTLS reply is malformed: its continuation lines carry different reply codes, so the upgrade was not attempted.") }
            guard st == 220 else { throw ProbeError(text: "STARTTLS returned \(st).") }
        case .imapStartTLS:
            let banner = try c.readLine(); log("S:", banner)
            guard banner.hasPrefix("* OK") else { throw ProbeError(text: "Unexpected IMAP greeting.") }
            try c.write("a1 STARTTLS\r\n"); log("C:", "a1 STARTTLS")
            for n in 0... {
                guard n < 100 else { throw ProbeError(text: "IMAP reply too long") }
                let l = try c.readLine(); log("S:", l)
                if l.uppercased().hasPrefix("* BYE") { throw ProbeError(text: "IMAP server closed the session: \(Wire.sanitize(l))") }
                if l.hasPrefix("a1 ") { guard l.uppercased().hasPrefix("A1 OK") else { throw ProbeError(text: "IMAP STARTTLS refused: \(Wire.sanitize(l))") }; break }
            }
        case .pop3StartTLS:
            let banner = try c.readLine(); log("S:", banner)
            guard banner.hasPrefix("+OK") else { throw ProbeError(text: "Unexpected POP3 greeting.") }
            try c.write("STLS\r\n"); log("C:", "STLS")
            let l = try c.readLine(); log("S:", l)
            guard l.hasPrefix("+OK") else { throw ProbeError(text: "POP3 STLS refused: \(Wire.sanitize(l))") }
        case .ldapStartTLS:
            try c.write(Wire.ldapStartTLSRequest()); log("C:", "ExtendedRequest StartTLS (\(Wire.ldapStartTLSOID))")
            let head = try c.read(2)
            var len = Int(head[1]); var lenBytes: [UInt8] = []
            if len & 0x80 != 0 { let n = len & 0x7F; guard n <= 4 else { throw ProbeError(text: "Bad LDAP response") }; lenBytes = try c.read(n); len = lenBytes.reduce(0) { $0 << 8 | Int($1) } }
            guard len < 65_536 else { throw ProbeError(text: "LDAP response too large") }
            let msg = head + lenBytes + (try c.read(len))
            guard let code = Wire.ldapExtendedResultCode(msg) else { throw ProbeError(text: "Server did not return an LDAP ExtendedResponse.") }
            log("S:", "ExtendedResponse resultCode \(code)")
            guard code == 0 else { throw ProbeError(text: "LDAP StartTLS refused (resultCode \(code)). Port 389 may require LDAPS on 636, or the DC has no certificate.") }
        case .mysql:
            let h = try c.read(4)
            let len = Int(h[0]) | Int(h[1]) << 8 | Int(h[2]) << 16
            guard len < 65_536 else { throw ProbeError(text: "MySQL greeting too large") }
            let g = try Wire.parseMySQLGreeting(try c.read(len))
            log("S:", "MySQL greeting, server \(g.version), TLS \(g.supportsTLS ? "supported" : "not offered")")
            guard g.supportsTLS else { throw ProbeError(text: "MySQL server \(g.version) does not offer TLS (CLIENT_SSL not set).") }
            try c.write(Wire.mysqlSSLRequest()); log("C:", "SSLRequest")
        case .rdp:
            try c.write(RDP.connectionRequest()); log("C:", "X.224 Connection Request, RDP_NEG_REQ PROTOCOL_SSL|PROTOCOL_HYBRID (no cookie, no credentials)")
            let neg: RDP.Negotiation
            do { neg = try RDP.parseConfirm(try c.read(try RDP.tpktLength(try c.read(4)))) }
            catch let e as CheckError { throw ProbeError(text: e.localizedDescription) }
            log("S:", RDP.describe(neg))
            r.negotiation = RDP.findings(neg)
            guard RDP.startsTLS(neg) else { throw ProbeError(text: RDP.describe(neg)) }
        default: break
        }
    }

    static func presented(_ trust: SecTrust) -> [Certificate] {
        var out: [Certificate] = []
        for i in 0..<SecTrustGetCertificateCount(trust) {
            if let c = SecTrustGetCertificateAtIndex(trust, i), let cert = try? Certificate(der: [UInt8](SecCertificateCopyData(c) as Data)) { out.append(cert) }
        }
        return out
    }

    static func negotiatedVersion(_ c: StreamConnection) -> String? {
        guard let v = c.input.property(forKey: Stream.PropertyKey(kCFStreamPropertySSLContext as String)) else { return nil }
        let cf = v as CFTypeRef
        guard CFGetTypeID(cf) == SSLContextGetTypeID() else { return nil }
        let ctx = cf as! SSLContext // type verified above
        var p = SSLProtocol.sslProtocolUnknown
        guard SSLGetNegotiatedProtocolVersion(ctx, &p) == errSecSuccess else { return nil }
        switch p { case .tlsProtocol1: return "TLS 1.0"; case .tlsProtocol11: return "TLS 1.1"; case .tlsProtocol12: return "TLS 1.2"; case .tlsProtocol13: return "TLS 1.3"; default: return nil }
    }

    /// Copy-only openssl command equivalent to this probe. Never executed by the app.
    public static func opensslCommand(_ t: Target) -> String {
        let q = Shell.quote
        // openssl s_client cannot perform the RDP X.224 negotiation; nmap's ssl-cert script can.
        if t.service == .rdp { return "nmap -Pn -p \(t.port) --script rdp-enum-encryption,ssl-cert \(q(t.host))" }
        var s = "\(Shell.openssl) s_client -connect \(q(t.endpoint)) -servername \(q(t.serverName)) -showcerts -verify_hostname \(q(t.verifyName))"
        if let st = t.service.opensslStartTLS { s += " -starttls \(st)" }
        return s + " </dev/null"
    }
}

/// Helpers for copy-only command text. Nothing here is ever executed by the app.
public enum Shell {
    /// For commands run on this Mac: /usr/bin/openssl is LibreSSL (no -starttls ldap/mysql, older options), so use
    /// Homebrew OpenSSL 3 wherever Homebrew is installed (Apple Silicon or Intel prefix).
    public static let openssl = "\"$(brew --prefix openssl@3)/bin/openssl\""
    /// For commands run on a server (Linux, pfSense, appliances): the platform's own openssl.
    public static let serverOpenSSL = "openssl"
    static let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:/@+,")
    /// POSIX single-quote unless every character is known safe.
    /// PowerShell single-quoted literal (embedded quotes doubled).
    public static func psQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "''") + "'" }
    public static func quote(_ s: String) -> String {
        if !s.isEmpty, s.unicodeScalars.allSatisfy({ safe.contains($0) }) { return s }
        return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
