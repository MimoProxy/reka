import XCTest
@testable import MimoReka

final class SubscriptionPlanUsageTests: XCTestCase {
    func testMissingValuesAreUnknownAndExplicitZeroDoesNotBecomeUnlimited() throws {
        XCTAssertNil(SubscriptionPlanUsage(value: .null))
        let unknown = try XCTUnwrap(SubscriptionPlanUsage(value: .object([:])))
        XCTAssertNil(unknown.used); XCTAssertNil(unknown.total); XCTAssertNil(unknown.expireUnix)
        let zero = try XCTUnwrap(SubscriptionPlanUsage(value: .object(["upload": .number(0), "download": .number(0), "total": .number(0), "expire_unix": .number(0)])))
        XCTAssertEqual(zero.used, 0); XCTAssertEqual(zero.total, 0); XCTAssertEqual(zero.expireUnix, 0)
        XCTAssertNil(zero.fractionUsed); XCTAssertNil(zero.remaining); XCTAssertNil(zero.expiresAt)
    }

    func testProviderCountersRemainSeparateAndProgressClampsOvershoot() throws {
        let usage = try XCTUnwrap(SubscriptionPlanUsage(value: .object(["upload": .number(40), "download": .number(80), "total": .number(100), "expire_unix": .number(1893456000)])))
        XCTAssertEqual(usage.used, 120); XCTAssertEqual(usage.remaining, 0); XCTAssertEqual(usage.fractionUsed, 1)
        XCTAssertEqual(usage.expiresAt?.timeIntervalSince1970, 1893456000)
        let partial = try XCTUnwrap(SubscriptionPlanUsage(value: .object(["upload": .number(40), "total": .number(100)])))
        XCTAssertNil(partial.used); XCTAssertNil(partial.remaining); XCTAssertNil(partial.fractionUsed)
    }

    func testLargeUnsignedCountersNeverWrapAndInvalidFieldsStayUnknown() throws {
        let usage = try XCTUnwrap(SubscriptionPlanUsage(value: .object(["upload": .number(Double(UInt64.max)), "download": .number(Double(UInt64.max)), "total": .number(1), "expire_unix": .number(-1), "invalid_fields": .array([.string("expire")]) ])))
        XCTAssertGreaterThan(usage.used ?? 0, Double(UInt64.max))
        XCTAssertTrue((usage.used ?? 0).isFinite)
        XCTAssertEqual(usage.fractionUsed, 1); XCTAssertNil(usage.expiresAt)
        XCTAssertEqual(usage.invalidFields, ["expire"])
        XCTAssertFalse(SubscriptionPlanUsage.bytes(usage.used!).contains("-"))
        let invalid = try XCTUnwrap(SubscriptionPlanUsage(value: .object(["upload": .number(-1), "download": .number(1.5)])))
        XCTAssertNil(invalid.upload); XCTAssertNil(invalid.download)
    }
}
