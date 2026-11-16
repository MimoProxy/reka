import XCTest
@testable import MimoReka

final class OperationsTests: XCTestCase {
    func testTrafficRatesNeverBridgeProcessEpochOrCounterReset() throws {
        let first = try sample(epoch: "first", upload: 100, download: 200, second: 1)
        let next = try sample(epoch: "first", upload: 500, download: 1000, second: 3)
        let rate = try XCTUnwrap(next.rates(since: first))
        XCTAssertEqual(rate.upload, 200)
        XCTAssertEqual(rate.download, 400)
        XCTAssertNil(try sample(epoch: "second", upload: 600, download: 1100, second: 4).rates(since: next))
        XCTAssertNil(try sample(epoch: "first", upload: 1, download: 1, second: 4).rates(since: next))
        XCTAssertNil(next.rates(since: next))
    }

    func testTrafficRejectsUnusableSamplesInsteadOfShowingFalseZero() {
        XCTAssertNil(TrafficSample(value: .object(["upload_total": .number(0), "download_total": .number(0)])))
        XCTAssertNil(TrafficSample(value: .object(["epoch": .string("a"), "upload_total": .number(-1), "download_total": .number(0), "sampled_at": .string("2026-11-16T12:00:00Z")])))
    }

    func testLogIdentityUsesEpochAndSequenceRatherThanMessage() throws {
        func event(_ epoch: String, _ sequence: Int) -> JSONValue {
            .object(["type": .string("log"), "epoch": .string(epoch), "seq": .number(Double(sequence)),
                     "time": .string("2026-11-16T12:00:00Z"),
                     "data": .object(["level": .string("warn"), "message": .string("same")])])
        }
        let first = try XCTUnwrap(CoreLogRow(event: event("a", 1)))
        XCTAssertNotEqual(first.id, CoreLogRow(event: event("a", 2))?.id)
        XCTAssertNotEqual(first.id, CoreLogRow(event: event("b", 1))?.id)
        XCTAssertEqual(first.level, "warn")
        XCTAssertTrue(first.text.contains("[WARN] same"))
        XCTAssertNil(CoreLogRow(event: .object(["type": .string("config.committed")])))
    }

    private func sample(epoch: String, upload: Double, download: Double, second: Int) throws -> TrafficSample {
        try XCTUnwrap(TrafficSample(value: .object([
            "epoch": .string(epoch), "upload_total": .number(upload), "download_total": .number(download),
            "sampled_at": .string(String(format: "2026-11-16T12:00:%02dZ", second))
        ])))
    }
}
