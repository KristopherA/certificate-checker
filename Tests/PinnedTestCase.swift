import XCTest

/// Every test class derives from this so checks see a fixed "now" (2026-11-15 00:00 UTC), inside every fixture's
/// validity window. Tests that need another date pass `now:` explicitly.
class PinnedTestCase: XCTestCase {
    static let pinnedNow = Date(timeIntervalSince1970: 1_794_700_800)
    override class func setUp() { super.setUp(); Clock.set { PinnedTestCase.pinnedNow } }
    override class func tearDown() { Clock.reset(); super.tearDown() }
}
