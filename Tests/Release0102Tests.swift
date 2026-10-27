import XCTest

/// 0.10.2: Target sheet layout floor, content-size clamp round-trip, config footer defaults.
final class Release0102Tests: XCTestCase {
    func testTargetEditorMetricsFloor() {
        XCTAssertEqual(TargetEditorMetrics.minWidth, 520)
        XCTAssertEqual(TargetEditorMetrics.minHeight, 480)
        XCTAssertGreaterThanOrEqual(TargetEditorMetrics.defaultWidth, TargetEditorMetrics.minWidth)
        XCTAssertGreaterThanOrEqual(TargetEditorMetrics.defaultHeight, TargetEditorMetrics.minHeight)
    }

    func testOrganizationNameDefaultRemainsEmpty() {
        XCTAssertEqual(AppConfig().organizationName, "")
        XCTAssertEqual(AppConfig().defaultDomain, "example.com")
    }

    /// Save-then-restore of a valid content size is stable (no growth from chrome mismatch).
    func testClampContentSizeRoundTripIsStable() {
        let maxW = 1440.0, maxH = 900.0
        let savedW = 640.0, savedH = 600.0
        let once = TargetEditorMetrics.clampContentSize(
            width: savedW, height: savedH, maxWidth: maxW, maxHeight: maxH)
        let twice = TargetEditorMetrics.clampContentSize(
            width: once.width, height: once.height, maxWidth: maxW, maxHeight: maxH)
        XCTAssertEqual(once.width, savedW)
        XCTAssertEqual(once.height, savedH)
        XCTAssertEqual(twice.width, once.width)
        XCTAssertEqual(twice.height, once.height)
    }

    func testClampContentSizeRaisesFloor() {
        let c = TargetEditorMetrics.clampContentSize(
            width: 100, height: 50, maxWidth: 2000, maxHeight: 1200)
        XCTAssertEqual(c.width, TargetEditorMetrics.minWidth)
        XCTAssertEqual(c.height, TargetEditorMetrics.minHeight)
    }

    func testClampContentSizeCapsAtScreen() {
        let c = TargetEditorMetrics.clampContentSize(
            width: 99999, height: 99999, maxWidth: 1280, maxHeight: 800)
        XCTAssertEqual(c.width, 1280)
        XCTAssertEqual(c.height, 800)
    }
}
