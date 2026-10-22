import Foundation

/// Minimal, bounds-checked DER reader. Never allocates more than the input size.
public struct DERNode: Equatable {
    public let tag: UInt8
    public let content: [UInt8]
    public let raw: [UInt8]
    public var constructed: Bool { tag & 0x20 != 0 }
    public var tagClass: UInt8 { tag & 0xC0 }
    public var tagNumber: UInt8 { tag & 0x1F }

    public func children() throws -> [DERNode] { try DER.parseAll(content) }

    public var oid: String? {
        guard tag == 0x06, !content.isEmpty else { return nil }
        var parts: [UInt64] = []
        var value: UInt64 = 0
        for (i, b) in content.enumerated() {
            value = (value << 7) | UInt64(b & 0x7F)
            if b & 0x80 == 0 {
                if parts.isEmpty && i < content.count {
                    let first = value < 80 ? value / 40 : 2
                    parts.append(first); parts.append(value - first * 40)
                } else { parts.append(value) }
                value = 0
            }
            if value > UInt64.max >> 8 { return nil }
        }
        return parts.map(String.init).joined(separator: ".")
    }

    public var string: String? {
        switch tag {
        case 0x0C, 0x13, 0x16, 0x14, 0x1A, 0x81, 0x82, 0x86: return String(decoding: content, as: UTF8.self)
        case 0x1E: // BMPString
            var units: [UInt16] = []
            var i = 0
            while i + 1 < content.count { units.append(UInt16(content[i]) << 8 | UInt16(content[i+1])); i += 2 }
            return String(decoding: units, as: UTF16.self)
        default: return nil
        }
    }

    /// Unsigned big-endian integer bytes without leading zero padding.
    public var unsignedInteger: [UInt8] {
        var c = content[...]
        while c.count > 1, c.first == 0 { c = c.dropFirst() }
        return Array(c)
    }

    public var intValue: Int? {
        guard tag == 0x02 || tag == 0x0A, !content.isEmpty, content.count <= 8 else { return nil }
        var v = Int(Int8(bitPattern: content[0]))
        for b in content.dropFirst() { v = (v << 8) | Int(b) }
        return v
    }

    /// BIT STRING payload without the unused-bits octet.
    public var bitStringBytes: [UInt8]? {
        guard tag == 0x03, !content.isEmpty else { return nil }
        return Array(content.dropFirst())
    }

    public var time: Date? {
        guard tag == 0x17 || tag == 0x18 else { return nil }
        let s = Array(String(decoding: content, as: UTF8.self))
        guard s.last == "Z" else { return nil }
        let digits = s.dropLast()
        guard digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        let d = digits.map { Int(String($0))! }
        func num(_ a: Int, _ n: Int) -> Int { d[a..<(a+n)].reduce(0) { $0 * 10 + $1 } }
        var c = DateComponents(); var o = 0
        if tag == 0x17 { guard d.count == 12 else { return nil }; let y = num(0, 2); c.year = y >= 50 ? 1900 + y : 2000 + y; o = 2 }
        else { guard d.count == 14 else { return nil }; c.year = num(0, 4); o = 4 }
        c.month = num(o, 2); c.day = num(o+2, 2); c.hour = num(o+4, 2); c.minute = num(o+6, 2); c.second = num(o+8, 2)
        var cal = Calendar(identifier: .gregorian); cal.timeZone = TimeZone(identifier: "UTC")!
        return cal.date(from: c)
    }
}

public enum DERError: Error, LocalizedError, Equatable {
    case truncated, badLength, tooDeep, unexpected(String)
    public var errorDescription: String? {
        switch self {
        case .truncated: return "The DER data is truncated."
        case .badLength: return "The DER data has an invalid length."
        case .tooDeep: return "The DER data is nested too deeply."
        case .unexpected(let s): return "Unexpected DER structure: \(s)."
        }
    }
}

public enum DER {
    public static func parse(_ bytes: [UInt8]) throws -> DERNode {
        var i = 0
        let n = try read(bytes, &i)
        return n
    }
    public static func parseAll(_ bytes: [UInt8]) throws -> [DERNode] {
        var i = 0; var out: [DERNode] = []
        while i < bytes.count { out.append(try read(bytes, &i)); if out.count > 10_000 { throw DERError.tooDeep } }
        return out
    }
    static func read(_ b: [UInt8], _ i: inout Int) throws -> DERNode {
        let start = i
        guard i < b.count else { throw DERError.truncated }
        let tag = b[i]; i += 1
        guard tag & 0x1F != 0x1F else { throw DERError.unexpected("high tag number") }
        guard i < b.count else { throw DERError.truncated }
        var len = Int(b[i]); i += 1
        if len & 0x80 != 0 {
            let count = len & 0x7F
            guard count > 0, count <= 4, i + count <= b.count else { throw DERError.badLength }
            len = 0
            for _ in 0..<count { len = (len << 8) | Int(b[i]); i += 1 }
        }
        guard len >= 0, i + len <= b.count else { throw DERError.truncated }
        let content = Array(b[i..<(i+len)]); i += len
        return DERNode(tag: tag, content: content, raw: Array(b[start..<i]))
    }

    // Encoders used for building requests and tests.
    public static func length(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var v = n; var bytes: [UInt8] = []
        while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
    public static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] { [tag] + length(content.count) + content }
}

public enum PEM {
    public struct Block: Equatable { public let label: String; public let der: [UInt8] }
    /// Extract all PEM blocks. Returns an empty array when the text has none.
    public static func blocks(_ text: String) -> [Block] {
        var out: [Block] = []
        var label: String?
        var body = ""
        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("-----BEGIN "), line.hasSuffix("-----") {
                label = String(line.dropFirst(11).dropLast(5)); body = ""
            } else if line.hasPrefix("-----END "), let l = label {
                if let d = Data(base64Encoded: body, options: .ignoreUnknownCharacters) { out.append(Block(label: l, der: [UInt8](d))) }
                label = nil; body = ""
            } else if label != nil, !line.contains(":") {
                body += line
            }
        }
        return out
    }
}
