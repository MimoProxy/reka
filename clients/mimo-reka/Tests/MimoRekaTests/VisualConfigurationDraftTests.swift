import XCTest
@testable import MimoReka

final class VisualConfigurationDraftTests: XCTestCase {
    func testUntouchedDraftDoesNotMaterializeDefaultsOrRewriteDocuments() throws {
        let documents: [ConfigurationLayer: String] = [
            .profile: "schema-version: 1\nimports: [{source: airport, outbounds: true, groups: true, rule-sets: true}]\n",
            .local: "listeners: [{id: mixed, type: mixed, listen: '127.0.0.1:17891', udp: false}]\ncontrol: {listen: 'unix:///tmp/specific.sock'}\n"
        ]
        let draft = try VisualConfigurationDraft(documents: documents, sourceNames: ["airport": "订阅", "inactive": "未启用来源"])
        XCTAssertEqual(draft.change(baseRevision: 4), ["base_revision": .number(4)])
    }

    func testControlledDNSAndListenerEditsPreserveAdvancedFields() throws {
        let documents: [ConfigurationLayer: String] = [
            .profile: """
            schema-version: 1
            dns:
              nameserver: [1.1.1.1]
              nameserver-policy: [{id: company, pattern: '+.company.test', servers: [192.0.2.53]}]
              fallback-filter: {geoip: false, domain: ['+.fallback.test']}
              ipv6: false
            """,
            .local: "listeners: [{id: mixed, type: mixed, listen: '127.0.0.1:17891', udp: false}]\ncontrol: {listen: 'unix:///tmp/specific.sock'}\n"
        ]
        var draft = try VisualConfigurationDraft(documents: documents, sourceNames: [:])
        draft.dns["ipv6"] = .bool(true)
        draft.listeners[0].listen = "127.0.0.1:17892"
        let change = draft.change(baseRevision: 4)
        let dns = try XCTUnwrap(change["patch"]?.arrayValue?.first?["value"].objectValue)
        XCTAssertEqual(dns["nameserver-policy"], draft.profile["dns"]?["nameserver-policy"])
        XCTAssertEqual(dns["fallback-filter"], draft.profile["dns"]?["fallback-filter"])
        XCTAssertEqual(dns["ipv6"], .bool(true))
        let listeners = try XCTUnwrap(change["local_patch"]?.arrayValue?.first?["value"].arrayValue)
        XCTAssertEqual(listeners[0]["udp"], .bool(false))
        XCTAssertEqual(listeners[0]["listen"], .string("127.0.0.1:17892"))
        XCTAssertEqual(change["local_patch"]?.arrayValue?.count, 1)
    }
}
