import Foundation

/// The single source of "now" for every check's default `now:` argument. Production always uses the real clock;
/// the test suite pins it to a fixed date so fixtures do not start failing when they expire.
public enum Clock {
    private static let lock = NSLock()
    private static var source: () -> Date = { Date() }
    /// Read by every check. Only code in this module (the test suite) can replace it.
    public static func now() -> Date { lock.lock(); defer { lock.unlock() }; return source() }
    static func set(_ f: @escaping () -> Date) { lock.lock(); source = f; lock.unlock() }
    static func reset() { set { Date() } }
}
