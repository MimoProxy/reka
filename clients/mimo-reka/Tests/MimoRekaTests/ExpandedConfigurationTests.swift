import XCTest
@testable import MimoReka

final class ExpandedConfigurationTests: XCTestCase {
    func testSniffDefaultsDoNotCreateConfigurationAndLocalOverrideKeepsItsLayer() throws {
        let empty = try VisualConfigurationDraft(documents: [.profile: "schema-version: 1\n", .local: "{}\n"], sourceNames: [:])
        XCTAssertTrue(empty.sniff.isEmpty)
        XCTAssertEqual(empty.change(baseRevision: 1), ["base_revision": .number(1)])
        let docs: [ConfigurationLayer: String] = [
            .profile: "sniff: {enabled: true, protocols: [tls]}\n",
            .local: "sniff: {enabled: false, timeout-ms: 450, max-bytes: 8192, max-packets: 3, override-destination: false}\n"
        ]
        var draft = try VisualConfigurationDraft(documents: docs, sourceNames: [:])
        XCTAssertEqual(draft.sniffLayer, .local)
        XCTAssertEqual(draft.sniff["enabled"], .bool(false))
        XCTAssertEqual(draft.change(baseRevision: 2), ["base_revision": .number(2)])
        draft.sniff["enabled"] = .bool(true)
        let change = draft.change(baseRevision: 2)
        XCTAssertNil(change["patch"])
        let edited = try XCTUnwrap(change["local_patch"]?.arrayValue?.first?["value"].objectValue)
        XCTAssertEqual(edited["timeout-ms"], .number(450))
        XCTAssertEqual(edited["max-bytes"], .number(8192))
        XCTAssertEqual(edited["override-destination"], .bool(false))
    }

    func testNewDNSControlsAndListenerAddressPreserveCredentialsAndUnknownFields() throws {
        let docs: [ConfigurationLayer: String] = [
            .profile: "dns: {nameserver: [1.1.1.1], cache-stale-ttl: 120, max-concurrent-upstreams: 2, use-system-hosts: true}\n",
            .local: "listeners: [{id: local, type: mixed, listen: '127.0.0.1:17891', users: [{username: Alice, password: '********'}]}]\n"
        ]
        var draft = try VisualConfigurationDraft(documents: docs, sourceNames: [:])
        draft.dns["cache-stale-ttl"] = .number(300)
        draft.listeners[0].listen = "127.0.0.1:17892"
        let change = draft.change(baseRevision: 3)
        let dns = try XCTUnwrap(change["patch"]?.arrayValue?.first?["value"].objectValue)
        XCTAssertEqual(dns["max-concurrent-upstreams"], .number(2))
        XCTAssertEqual(dns["use-system-hosts"], .bool(true))
        let listener = try XCTUnwrap(change["local_patch"]?.arrayValue?.first?["value"].arrayValue?.first)
        XCTAssertEqual(listener["users"].arrayValue?.first?["password"], .string("********"))
    }

    func testNestedXHTTPEditPreservesIndependentTLSAndReuseFields() throws {
        let tls: JSONValue = .object(["server-name": .string("download.test"), "certificate-sha256": .string("pin"), "ech": .object(["enabled": .bool(true), "config": .string("protected")]), "private-key": .string("********")])
        var transport: [String: JSONValue] = [
            "type": .string("xhttp"), "headers": .array([.object(["name": .string("X-Key"), "value": .string("********")])]),
            "xhttp": .object(["mode": .string("auto"), "x-padding-bytes": .string("100-200"), "download-settings": .object(["server": .string("download.test"), "tls": tls, "xmux": .object(["max-concurrency": .string("10-20"), "h-keep-alive-period": .string("10")])])])
        ]
        let headers = transport["headers"]
        NativeFieldEditing.set(&transport, path: ["xhttp", "download-settings", "xmux", "max-concurrency"], value: .string("20-30"))
        XCTAssertEqual(NativeFieldEditing.value(transport, path: ["xhttp", "download-settings", "tls"]), tls)
        XCTAssertEqual(NativeFieldEditing.value(transport, path: ["xhttp", "download-settings", "xmux", "h-keep-alive-period"]), .string("10"))
        XCTAssertEqual(transport["headers"], headers)
        NativeFieldEditing.set(&transport, path: ["xhttp", "download-settings", "tls", "ech"], value: nil)
        XCTAssertEqual(NativeFieldEditing.value(transport, path: ["xhttp", "download-settings", "tls", "private-key"]), .string("********"))
        XCTAssertEqual(NativeFieldEditing.value(transport, path: ["xhttp", "x-padding-bytes"]), .string("100-200"))
    }
}
