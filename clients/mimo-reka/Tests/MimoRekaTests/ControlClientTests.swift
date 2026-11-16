import XCTest
import Darwin
@testable import MimoReka

final class ControlClientTests: XCTestCase, @unchecked Sendable {
    func testNestedPatchUsesStableWireOrderForPlanHash() async throws {
        let server = try TestUnixServer()
        let serving = server.serve { descriptor in
            _ = try TestUnixServer.receive(descriptor)
            try TestUnixServer.reply(descriptor, .object(["id": .number(1), "result": .object(["version": .number(1)])]))
            let raw = String(decoding: try TestUnixServer.receiveData(descriptor), as: UTF8.self)
            // Reka preserves patch-value key order in YAML and hashes the
            // resulting bytes. The exact same candidate must survive a commit.
            XCTAssertEqual(raw, #"{"id":2,"method":"PlanConfiguration","params":{"base_revision":1,"overlay_patch":[{"op":"insert","path":"/patches","value":{"op":"set","path":"/groups/main~1choice/selected","value":"main/node"}}]}}"#)
            try TestUnixServer.reply(descriptor, .object(["id": .number(2), "result": .object([:])]))
        }
        _ = try await RekaControlClient(socketPath: server.path).call("PlanConfiguration", params: [
            "overlay_patch": .array([.object([
                "value": .object(["value": .string("main/node"), "path": .string("/groups/main~1choice/selected"), "op": .string("set")]),
                "path": .string("/patches"), "op": .string("insert")
            ])]), "base_revision": .number(1)
        ])
        try await serving.value
    }

    func testNegotiatesHelloAndReadsFragmentedReply() async throws {
        let server = try TestUnixServer()
        let serving = server.serve { descriptor in
            let hello = try TestUnixServer.receive(descriptor)
            XCTAssertEqual(hello["method"].stringValue, "Hello")
            XCTAssertEqual(hello["params"]["versions"], .array([.number(1)]))
            try TestUnixServer.reply(descriptor, .object(["id": .number(1), "result": .object(["version": .number(1)])]))
            let request = try TestUnixServer.receive(descriptor)
            XCTAssertEqual(request["method"].stringValue, "GetStatus")
            try TestUnixServer.reply(descriptor, .object(["id": .number(2), "result": .object([
                "revision": .number(7), "runtime": .object(["connections": .number(3)])
            ])]), fragmented: true)
        }
        let result = try await RekaControlClient(socketPath: server.path).call("GetStatus")
        XCTAssertEqual(result["revision"].intValue, 7)
        XCTAssertEqual(result["runtime"]["connections"].intValue, 3)
        try await serving.value
    }

    func testPreservesServerErrorCodeAndMessage() async throws {
        let server = try TestUnixServer()
        let serving = server.serve { descriptor in
            _ = try TestUnixServer.receive(descriptor)
            try TestUnixServer.reply(descriptor, .object(["id": .number(1), "result": .object(["version": .number(1)])]))
            _ = try TestUnixServer.receive(descriptor)
            try TestUnixServer.reply(descriptor, .object(["id": .number(2), "error": .object([
                "code": .string("conflict"), "message": .string("stale revision")
            ])]))
        }
        do {
            _ = try await RekaControlClient(socketPath: server.path).call("PlanConfiguration")
            XCTFail("Expected a server error")
        } catch RekaControlError.server(let code, let message) {
            XCTAssertEqual(code, "conflict")
            XCTAssertEqual(message, "stale revision")
        }
        try await serving.value
    }

    func testRejectsOversizedFrameBeforeAllocatingIt() async throws {
        let server = try TestUnixServer()
        let serving = server.serve { descriptor in
            _ = try TestUnixServer.receive(descriptor)
            try TestUnixServer.send(descriptor, Data([0x01, 0x00, 0x00, 0x01]))
        }
        do {
            _ = try await RekaControlClient(socketPath: server.path).call("GetStatus")
            XCTFail("Expected a protocol error")
        } catch RekaControlError.protocolError { }
        try await serving.value
    }

    func testRequestHasAFiniteDeadline() async throws {
        let server = try TestUnixServer()
        let serving = server.serve { descriptor in
            _ = try TestUnixServer.receive(descriptor)
            usleep(150_000)
        }
        do {
            _ = try await RekaControlClient(socketPath: server.path, timeout: 0.05).call("GetStatus")
            XCTFail("Expected a deadline error")
        } catch RekaControlError.timeout { }
        try await serving.value
    }

    func testUnexpectedResponseIDIsRejected() async throws {
        let server = try TestUnixServer()
        let serving = server.serve { descriptor in
            _ = try TestUnixServer.receive(descriptor)
            try TestUnixServer.reply(descriptor, .object(["id": .number(99), "result": .null]))
        }
        do {
            _ = try await RekaControlClient(socketPath: server.path).call("GetStatus")
            XCTFail("Expected a protocol error")
        } catch RekaControlError.protocolError { }
        try await serving.value
    }
}

/// A bounded local fixture that speaks the public wire protocol independently.
private final class TestUnixServer: @unchecked Sendable {
    let path = "/tmp/reka-swift-" + UUID().uuidString + ".sock"
    private let descriptor: Int32

    init() throws {
        descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw POSIXError(.EIO) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8) + [UInt8(0)]
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, listen(descriptor, 1) == 0 else { throw POSIXError(.EIO) }
    }

    deinit {
        close(descriptor)
        unlink(path)
    }

    func serve(_ response: @escaping @Sendable (Int32) throws -> Void) -> Task<Void, Error> {
        Task.detached {
            var ready = pollfd(fd: self.descriptor, events: Int16(POLLIN), revents: 0)
            guard poll(&ready, 1, 2000) > 0 else { throw POSIXError(.ETIMEDOUT) }
            let client = accept(self.descriptor, nil, nil)
            guard client >= 0 else { throw POSIXError(.EIO) }
            defer { close(client) }
            var noSignal: Int32 = 1
            setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
            var timeout = timeval(tv_sec: 2, tv_usec: 0)
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            try response(client)
        }
    }

    static func receive(_ descriptor: Int32) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: receiveData(descriptor))
    }

    static func receiveData(_ descriptor: Int32) throws -> Data {
        let header = try exact(descriptor, count: 4)
        let count = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count < 16 * 1024 * 1024 else { throw POSIXError(.EMSGSIZE) }
        return try exact(descriptor, count: Int(count))
    }

    static func exact(_ descriptor: Int32, count: Int) throws -> Data {
        var bytes = Data(count: count)
        try bytes.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
            var offset = 0
            while offset < count {
                let amount = recv(descriptor, buffer.baseAddress!.advanced(by: offset), count - offset, 0)
                guard amount > 0 else { throw POSIXError(.ECONNRESET) }
                offset += amount
            }
        }
        return bytes
    }

    static func reply(_ descriptor: Int32, _ value: JSONValue, fragmented: Bool = false) throws {
        let body = try JSONEncoder().encode(value)
        let size = UInt32(body.count)
        var bytes = Data([UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)])
        bytes.append(body)
        if fragmented {
            for byte in bytes { try send(descriptor, Data([byte])) }
        } else { try send(descriptor, bytes) }
    }

    static func send(_ descriptor: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            var offset = 0
            while offset < data.count {
                let amount = Darwin.send(descriptor, buffer.baseAddress!.advanced(by: offset), data.count - offset, 0)
                guard amount > 0 else { throw POSIXError(.EIO) }
                offset += amount
            }
        }
    }
}
