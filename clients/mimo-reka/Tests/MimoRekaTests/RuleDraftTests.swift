import XCTest
@testable import MimoReka

final class RuleDraftTests: XCTestCase {
    func testChangingExitRetainsLogicalMatchAndImportedIdentity() throws {
        let match: JSONValue = .object(["and": .array([
            .object(["domain-regex": .string(#"(^|\.)example\.com$"#)]),
            .object(["not": .array([.object(["network": .string("udp")])])])
        ])])
        let original: [String: JSONValue] = ["id": .string("airport/r-complex"), "match": match, "outbound": .string("airport/old")]
        var draft = RuleDraft(definition: original)
        XCTAssertTrue(draft.preservesComplexMatch)
        draft.outbound = "airport/new"
        let result = try draft.definition()
        XCTAssertEqual(result["match"], match)
        XCTAssertEqual(result["id"], original["id"])
        XCTAssertEqual(result["outbound"], .string("airport/new"))
    }

    func testChangingExitDoesNotConvertAnExistingNumericOrScalarMatch() throws {
        let original: [String: JSONValue] = ["match": .object(["dst-port": .number(443)]), "outbound": .string("direct")]
        var draft = RuleDraft(definition: original)
        draft.outbound = "proxy"
        let result = try draft.definition()
        XCTAssertEqual(result["match"], original["match"])
        XCTAssertNil(result["id"], "Existing positional rules must retain their identity.")
    }

    func testExplicitMatchReplacementRemovesLogicalConditionAndOldModifier() throws {
        var draft = RuleDraft(definition: ["id": .string("rule-a"), "match": .object([
            "and": .array([.object(["ip-cidr": .string("10.0.0.0/8")])]), "no-resolve": .bool(true)
        ]), "outbound": .string("direct")])
        draft.replaceComplexMatch = true
        draft.condition = "all"
        let result = try draft.definition()
        XCTAssertEqual(result["match"], .object(["all": .bool(true)]))
    }

    func testSubRuleTargetIsPreservedUntilActionExplicitlyChanges() throws {
        let original: [String: JSONValue] = ["id": .string("sub-call"), "match": .object(["domain": .string("example.com")]), "call": .string("airport/sub")]
        var draft = RuleDraft(definition: original)
        XCTAssertEqual(try draft.definition(), original)
        draft.action = "outbound"
        draft.outbound = "direct"
        let result = try draft.definition()
        XCTAssertNil(result["call"])
        XCTAssertEqual(result["outbound"], .string("direct"))
    }

    func testRegexWhitespaceIsSignificantWhenEditingValues() throws {
        var draft = RuleDraft()
        draft.condition = "domain-regex"
        draft.valuesText = "  ^example\\.com$  "
        let result = try draft.definition()
        XCTAssertEqual(result["match"]?["domain-regex"], .string("  ^example\\.com$  "))
    }
}
