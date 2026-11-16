import Foundation
import Darwin

enum RekaControlError: LocalizedError, Sendable {
    case transport(String)
    case timeout
    case protocolError(String)
    case server(code: String, message: String)

    var errorDescription: String? {
        switch self {
        case .transport(let message): return "无法连接 Reka：\(message)"
        case .timeout: return "Reka 请求超时，请刷新状态后重试。"
        case .protocolError(let message): return "Reka 控制协议错误：\(message)"
        case .server(let code, let message): return "\(message)（\(code)）"
        }
    }
}

/// A request owns its socket, negotiates Hello, then closes it after the reply.
/// This keeps failures isolated and never blocks the application's main actor.
actor RekaControlClient {
    let socketPath: String
    private let timeout: TimeInterval

    init(socketPath: String, timeout: TimeInterval = 15) {
        self.socketPath = socketPath
        self.timeout = timeout
    }

    func call(_ method: String, params: [String: JSONValue] = [:]) async throws -> JSONValue {
        try Task.checkCancellation()
        let socketPath = socketPath
        let timeout = timeout
        return try await Task.detached(priority: .userInitiated) {
            try Self.perform(socketPath: socketPath, timeout: timeout, method: method, params: params)
        }.value
    }

    private static let maximumFrame = 16 * 1024 * 1024

    private static func perform(socketPath: String, timeout: TimeInterval,
                                method: String, params: [String: JSONValue]) throws -> JSONValue {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = Array(socketPath.utf8) + [UInt8(0)]
        guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw RekaControlError.transport("控制套接字路径过长")
        }
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            bytes.copyBytes(from: path)
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw systemError() }
        defer { Darwin.close(descriptor) }
        var noSignal: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                         socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw systemError() }
        guard fcntl(descriptor, F_SETFL, O_NONBLOCK) != -1 else { throw systemError() }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connected != 0 {
            guard errno == EINPROGRESS else { throw systemError() }
            try wait(descriptor, event: Int16(POLLOUT), deadline: deadline)
            var code: Int32 = 0
            var size = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &code, &size) == 0 else { throw systemError() }
            guard code == 0 else { throw systemError(code) }
        }
        let hello = try exchange(descriptor, id: 1, method: "Hello", params: [
            "versions": .array([.number(1)]), "client": .string("reka-mac/0.1")
        ], deadline: deadline)
        guard hello["version"].intValue == 1 else {
            throw RekaControlError.protocolError("内核未协商受支持的 API 版本")
        }
        return try exchange(descriptor, id: 2, method: method, params: params, deadline: deadline)
    }

    private static func exchange(_ descriptor: Int32, id: Int, method: String,
                                 params: [String: JSONValue], deadline: TimeInterval) throws -> JSONValue {
        let request = JSONValue.object([
            "id": .number(Double(id)), "method": .string(method), "params": .object(params)
        ])
        // Patch values become ordered YAML nodes in the kernel. Preserve the
        // same nested key order between PlanConfiguration and its commit.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let body = try encoder.encode(request)
        guard body.count <= maximumFrame else { throw RekaControlError.protocolError("请求超过 16 MiB") }
        let size = UInt32(body.count)
        var frame = Data([UInt8((size >> 24) & 255), UInt8((size >> 16) & 255),
                          UInt8((size >> 8) & 255), UInt8(size & 255)])
        frame.append(body)
        try write(descriptor, data: frame, deadline: deadline)
        let header = try read(descriptor, count: 4, deadline: deadline)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= maximumFrame else { throw RekaControlError.protocolError("响应帧长度无效") }
        let response = try JSONDecoder().decode(JSONValue.self,
            from: read(descriptor, count: Int(length), deadline: deadline))
        guard response["id"].intValue == id else { throw RekaControlError.protocolError("响应编号不匹配") }
        if let error = response["error"].objectValue {
            throw RekaControlError.server(code: error["code"]?.stringValue ?? "unknown",
                                          message: error["message"]?.stringValue ?? "请求失败")
        }
        return response["result"]
    }

    private static func read(_ descriptor: Int32, count: Int, deadline: TimeInterval) throws -> Data {
        var result = Data(count: count)
        try result.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
            var received = 0
            while received < count {
                try wait(descriptor, event: Int16(POLLIN), deadline: deadline)
                let amount = Darwin.recv(descriptor, buffer.baseAddress!.advanced(by: received), count - received, 0)
                if amount > 0 { received += amount }
                else if amount == 0 { throw RekaControlError.transport("控制连接已关闭") }
                else if errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { throw systemError() }
            }
        }
        return result
    }

    private static func write(_ descriptor: Int32, data: Data, deadline: TimeInterval) throws {
        try data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            var sent = 0
            while sent < data.count {
                try wait(descriptor, event: Int16(POLLOUT), deadline: deadline)
                let amount = Darwin.send(descriptor, buffer.baseAddress!.advanced(by: sent), data.count - sent, 0)
                if amount > 0 { sent += amount }
                else if amount == 0 { throw RekaControlError.transport("控制连接已关闭") }
                else if errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK { throw systemError() }
            }
        }
    }

    private static func wait(_ descriptor: Int32, event: Int16, deadline: TimeInterval) throws {
        while true {
            try Task.checkCancellation()
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw RekaControlError.timeout }
            var item = pollfd(fd: descriptor, events: event, revents: 0)
            let result = Darwin.poll(&item, 1, Int32(min(remaining * 1000, Double(Int32.max))))
            if result > 0 {
                if item.revents & event != 0 { return }
                throw RekaControlError.transport("控制连接已关闭")
            }
            if result == 0 { throw RekaControlError.timeout }
            if errno != EINTR { throw systemError() }
        }
    }

    private static func systemError(_ code: Int32 = errno) -> RekaControlError {
        .transport(String(cString: strerror(code)))
    }
}
