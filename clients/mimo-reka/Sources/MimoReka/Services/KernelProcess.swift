import AppKit
import CryptoKit
import Darwin
import Foundation
import Observation

/// Owns only this profile's supervised runtime. GUI crashes are observed by
/// MimoRekaHost, independently of application termination callbacks.
@MainActor @Observable
final class KernelProcess {
    private(set) var isRunning = false
    private(set) var isPrivileged: Bool
    private(set) var corePID: Int32?
    private(set) var logText = ""
    let stateRoot: URL
    var socketPath: String { isPrivileged ? controlDirectory + "/control.sock" : normalControlDirectory + "/" + profileKey + ".sock" }
    var runtimeStateRoot: String { isPrivileged ? "/Library/Application Support/MimoReka/\(getuid())/\(profileKey)/state" : stateRoot.path }

    @ObservationIgnored private var process: Process?
    @ObservationIgnored private var lifetime: Pipe?
    @ObservationIgnored private var output: Pipe?
    @ObservationIgnored private var isStarting = false
    @ObservationIgnored private var rootLogOffset: UInt64 = 0
    @ObservationIgnored private var logTask: Task<Void, Never>?
    @ObservationIgnored private var sessionToken = UUID().uuidString
    private var profileKey: String {
        if let identifier = UUID(uuidString: stateRoot.lastPathComponent) { return identifier.uuidString.lowercased() }
        return String(SHA256.hash(data: Data(stateRoot.standardizedFileURL.path.utf8)).map { String(format: "%02x", $0) }.joined().prefix(32))
    }
    private var controlDirectory: String { "/var/run/mimo-reka/\(getuid())/\(profileKey)" }
    private var normalControlDirectory: String { "/tmp/mimo-reka-\(getuid())" }
    private var hostSocketPath: String { controlDirectory + "/host.sock" }

    init(stateRoot: URL? = nil, privileged: Bool = false) {
        if let stateRoot { self.stateRoot = stateRoot }
        else if let path = ProcessInfo.processInfo.environment["MIMO_REKA_STATE_ROOT"], !path.isEmpty { self.stateRoot = URL(fileURLWithPath: path, isDirectory: true) }
        else { self.stateRoot = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/MimoReka/profiles/00000000-0000-4000-8000-000000000001", isDirectory: true) }
        isPrivileged = privileged
    }

    func start() async throws {
        guard !isStarting, process?.isRunning != true else { return }
        isStarting = true
        defer { isStarting = false }
        if isPrivileged { try await startPrivileged(bootstrap: nil) } else { try await startNormal() }
    }

    /// Explicitly promotes the current four documents into a private root
    /// runtime. The old user state remains an untouched rollback archive.
    func promote(configuration: JSONValue, resourceHashes: Set<String>? = nil) async throws {
        guard !isPrivileged else { return }
        guard configuration["effective"]["network"]["mode"].stringValue == "off" else { throw RekaControlError.transport("请先关闭当前网络接管，再授权网络模式。") }
        var documents: [String: String] = [:]
        for field in ["profile", "local", "sources", "overlay"] {
            guard let text = configuration[field].stringValue else { throw RekaControlError.transport("缺少 \(field) 配置，无法授权迁移。") }
            guard !text.contains("secret://") else { throw RekaControlError.transport("当前配置使用登录钥匙串 secret:// 引用。试用版暂不支持迁移这些秘密；请创建使用内联凭据的独立配置后授权。") }
            documents[field] = text
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mimo-reka-promotion-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let staging = directory.appendingPathComponent("bootstrap.json")
        let resources = try stageResources(into: directory, allowed: resourceHashes)
        let bundle: [String: Any] = ["documents": documents, "resources": resources]
        try JSONSerialization.data(withJSONObject: bundle, options: [.sortedKeys]).write(to: staging, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: staging.path)
        await stop()
        guard !isRunning else { throw RekaControlError.transport("原内核尚未完成停止，请稍后重试。") }
        isPrivileged = true
        do { try await startPrivileged(bootstrap: staging) }
        catch {
            let failure = error
            await stop()
            guard !isRunning else { throw RekaControlError.transport("授权启动未完成，网络运行时仍在清理。") }
            isPrivileged = false
            try await startNormal()
            throw failure
        }
    }

    func stop() async {
        logTask?.cancel(); logTask = nil
        if isPrivileged {
            do { _ = try await HostControl.request(path: hostSocketPath, command: "stop " + sessionToken) }
            catch {
                if process?.isRunning == true { appendLog("\n停止服务失败：\(error.localizedDescription)\n"); isRunning = true; return }
            }
        } else { try? lifetime?.fileHandleForWriting.close(); lifetime = nil }
        guard let child = process else { isRunning = false; corePID = nil; return }
        for _ in 0..<300 {
            if !child.isRunning { break }
            await Task.detached { try? await Task.sleep(for: .milliseconds(100)) }.value
        }
        isRunning = child.isRunning
        if !isRunning { corePID = nil; process = nil }
        else { appendLog("\n正在等待 Reka 完成网络恢复。\n") }
    }

    private func startNormal() async throws {
        let manager = FileManager.default
        try manager.createDirectory(at: stateRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if mkdir(normalControlDirectory, 0o700) != 0, errno != EEXIST { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var controlInfo = stat()
        guard lstat(normalControlDirectory, &controlInfo) == 0, (controlInfo.st_mode & S_IFMT) == S_IFDIR,
              controlInfo.st_uid == getuid(), controlInfo.st_mode & 0o077 == 0 else { throw RekaControlError.transport("本地控制目录权限不安全，无法启动。") }
        var arguments = ["--supervise", try coreExecutable().path, stateRoot.path, socketPath]
        if !manager.fileExists(atPath: stateRoot.appendingPathComponent("active.json").path) {
            let bootstrap = stateRoot.appendingPathComponent("bootstrap", isDirectory: true)
            try manager.createDirectory(at: bootstrap, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let profile = bootstrap.appendingPathComponent("profile.yaml"), local = bootstrap.appendingPathComponent("local.yaml")
            try Self.initialProfile.write(to: profile, atomically: true, encoding: .utf8)
            try Self.initialLocal(port: Self.bootstrapPort()).write(to: local, atomically: true, encoding: .utf8)
            for file in [profile, local] { try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path) }
            arguments += [profile.path, local.path]
        }
        let child = Process(), life = Pipe(), pipe = Pipe()
        child.executableURL = try hostExecutable(); child.arguments = arguments
        child.standardInput = life; child.standardOutput = pipe; child.standardError = pipe
        setupOutput(pipe); setupTermination(child)
        lifetime = life; process = child; logText = ""
        try child.run()
        try? life.fileHandleForReading.close()
        isRunning = true
        do { try await waitUntilReady(child) }
        catch { await stop(); throw error }
    }

    private func startPrivileged(bootstrap: URL?) async throws {
        sessionToken = UUID().uuidString
        var arguments = [try hostExecutable().path, "--privileged", String(getuid()), String(ProcessInfo.processInfo.processIdentifier), profileKey, try coreExecutable().path, sessionToken]
        if let bootstrap { arguments += [bootstrap.path] }
        let command = arguments.map(Self.shellQuote).joined(separator: " ")
        let script = "do shell script " + Self.appleScriptQuote(command) + " with administrator privileges with prompt \"Mimo Reka 需要授权独立的网络运行时，以管理系统代理或 TUN。\""
        let child = Process(), pipe = Pipe()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/osascript"); child.arguments = ["-e", script]
        child.standardOutput = pipe; child.standardError = pipe
        setupOutput(pipe); setupTermination(child)
        process = child; rootLogOffset = 0; logText = "等待 macOS 管理员授权…\n"
        try child.run(); isRunning = true
        do {
            try await waitUntilReady(child, attempts: 1800)
            corePID = Int32(try await HostControl.request(path: hostSocketPath, command: "status " + sessionToken).trimmingCharacters(in: .whitespacesAndNewlines))
            logTask = Task { [weak self] in
                while !Task.isCancelled {
                    guard let self else { return }
                    self.readRootLog()
                    try? await Task.sleep(for: .seconds(1))
                }
            }
        } catch {
            if child.isRunning { _ = try? await HostControl.request(path: hostSocketPath, command: "stop " + sessionToken) }
            if !child.isRunning { isRunning = false }
            throw error
        }
    }

    private func waitUntilReady(_ child: Process, attempts: Int = 100) async throws {
        let client = RekaControlClient(socketPath: socketPath, timeout: 1)
        for _ in 0..<attempts {
            guard child.isRunning else {
                isRunning = false
                let cancelled = logText.contains("User canceled") || logText.contains("用户已取消") || logText.contains("(-128)")
                throw RekaControlError.transport(cancelled ? "已取消管理员授权。" : "内核启动失败，请查看日志。")
            }
            if isPrivileged {
                let owned = try? await HostControl.request(path: hostSocketPath, command: "status " + sessionToken)
                guard let owned, let pid = Int32(owned.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 0 else {
                    try await Task.sleep(for: .milliseconds(100)); continue
                }
                corePID = pid
            } else if corePID == nil {
                try await Task.sleep(for: .milliseconds(100)); continue
            }
            do {
                // A configuration error leaves the daemon available for
                // document editing and history recovery in the main window.
                _ = try await client.call("GetStatus")
                return
            }
            catch RekaControlError.server(let code, let message) { throw RekaControlError.server(code: code, message: message) }
            catch { try await Task.sleep(for: .milliseconds(100)) }
        }
        await stop()
        throw RekaControlError.transport("内核启动超时，请查看日志。")
    }

    private func setupOutput(_ pipe: Pipe) {
        output?.fileHandleForReading.readabilityHandler = nil; output = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            Task { @MainActor [weak self] in
                let text = String(decoding: data, as: UTF8.self)
                for line in text.components(separatedBy: .newlines) where line.hasPrefix("MIMO_REKA_CORE_PID=") { self?.corePID = Int32(line.dropFirst("MIMO_REKA_CORE_PID=".count)) }
                self?.appendLog(text)
            }
        }
    }
    private func setupTermination(_ child: Process) {
        child.terminationHandler = { [weak self] ended in
            Task { @MainActor [weak self] in
                guard let self, self.process === ended else { return }
                self.isRunning = false; self.corePID = nil
                self.readRootLog(); self.logTask?.cancel()
                self.appendLog("\nReka 已退出（状态 \(ended.terminationStatus)）。\n")
            }
        }
    }
    private func readRootLog() {
        guard isPrivileged, let handle = FileHandle(forReadingAtPath: controlDirectory + "/core.log") else { return }
        defer { try? handle.close() }
        do {
            try handle.seek(toOffset: rootLogOffset)
            let data = try handle.readToEnd() ?? Data(); rootLogOffset += UInt64(data.count)
            if !data.isEmpty { appendLog(String(decoding: data, as: UTF8.self)) }
        } catch { }
    }
    private func appendLog(_ text: String) { logText.append(text); if logText.utf8.count > 131_072 { logText = String(logText.suffix(96_000)) } }
    /// Copy only authenticated immutable resource blobs, never arbitrary files
    /// referenced by foreign configurations. Root verifies every digest again.
    private func stageResources(into directory: URL, allowed: Set<String>?) throws -> [String] {
        let manager = FileManager.default
        let source = stateRoot.appendingPathComponent("resources/sha256", isDirectory: true)
        guard manager.fileExists(atPath: source.path) else {
            guard allowed?.isEmpty != false else { throw RekaControlError.transport("缺少配置引用的资源，无法授权迁移。") }; return []
        }
        let destination = directory.appendingPathComponent("sha256", isDirectory: true)
        try manager.createDirectory(at: destination, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var names: [String] = [], total = 0
        for file in try manager.contentsOfDirectory(at: source, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]) {
            let name = file.lastPathComponent
            guard name.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else { continue }
            let attributes = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            guard attributes.isRegularFile == true, attributes.isSymbolicLink != true else { throw RekaControlError.transport("资源缓存包含非普通文件，无法安全迁移。") }
            total += attributes.fileSize ?? 0
            guard total <= 512 * 1024 * 1024 else { throw RekaControlError.transport("迁移资源超过 512 MiB，请使用新的精简配置后授权。") }
            let data = try Data(contentsOf: file)
            let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            guard digest == name else { throw RekaControlError.transport("资源缓存校验失败，未修改当前运行配置。") }
            let target = destination.appendingPathComponent(name)
            try data.write(to: target, options: .atomic)
            try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            names.append(name)
        }
        if let allowed, Set(names) != allowed { throw RekaControlError.transport("配置引用的资源不完整，无法授权迁移。") }
        return names.sorted()
    }
    private func coreExecutable() throws -> URL {
        let environment = ProcessInfo.processInfo.environment
        let override = environment["MIMO_REKA_KERNEL_BINARY"] ?? environment["REKA_MAC_KERNEL_BINARY"]
        let url = override.map { URL(fileURLWithPath: $0) } ?? Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/reka")
        guard FileManager.default.isExecutableFile(atPath: url.path) else { throw RekaControlError.transport("应用中缺少 Reka 内核，请重新构建。") }; return url
    }
    private func hostExecutable() throws -> URL {
        let url = ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"].map { URL(fileURLWithPath: $0) } ?? Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/MimoRekaHost")
        guard FileManager.default.isExecutableFile(atPath: url.path) else { throw RekaControlError.transport("应用中缺少独立的 Mimo Reka 进程监督器，请重新构建。") }; return url
    }
    private static func shellQuote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    private static func appleScriptQuote(_ text: String) -> String { "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" }
    private static let initialProfile = """
    schema-version: 1
    groups:
      - {id: proxy, name: 默认策略, type: select, members: [direct], selected: direct}
    rules:
      - {id: lan-domain, match: {domain-suffix: [lan, local]}, outbound: direct}
      - {id: lan-ip, match: {ip-cidr: [127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16], no-resolve: true}, outbound: direct}
      - {id: final, match: {all: true}, outbound: proxy}
    """
    private static func initialLocal(port: Int) -> String { """
    listeners:
      - {id: mixed, type: mixed, listen: "127.0.0.1:\(port)"}
    network: {mode: off}
    """ }
    private static func bootstrapPort() throws -> Int {
        let value = ProcessInfo.processInfo.environment["MIMO_REKA_LISTEN_PORT"] ?? ProcessInfo.processInfo.environment["REKA_MAC_LISTEN_PORT"]
        let preferred: Int
        if let value { guard let port = Int(value) else { throw RekaControlError.transport("监听端口必须为整数。") }; preferred = port }
        else { preferred = 17891 }
        guard (0...65535).contains(preferred) else { throw RekaControlError.transport("监听端口必须为 0 至 65535。") }
        if let port = try availablePort(preferred) { return port }
        if value != nil { throw RekaControlError.transport("指定的监听端口已被占用。") }
        for _ in 0..<8 { if let port = try availablePort(0) { return port } }
        throw RekaControlError.transport("无法分配本地代理端口。")
    }
    private static func availablePort(_ preferred: Int) throws -> Int? {
        let tcp = Darwin.socket(AF_INET, SOCK_STREAM, 0), udp = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        guard tcp >= 0, udp >= 0 else { if tcp >= 0 { close(tcp) }; if udp >= 0 { close(udp) }; throw POSIXError(.EIO) }
        defer { close(tcp); close(udp) }
        var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1"); address.sin_port = UInt16(preferred).bigEndian
        func bindSocket(_ descriptor: Int32) throws -> Bool {
            let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            if result == 0 { return true }; if errno == EADDRINUSE { return false }; throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard try bindSocket(tcp) else { return nil }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(tcp, $0, &length) } }) == 0 else { throw POSIXError(.EIO) }
        guard try bindSocket(udp) else { return nil }; return Int(UInt16(bigEndian: address.sin_port))
    }
}

private enum HostControl {
    static func request(path: String, command: String) async throws -> String {
        try await Task.detached {
            let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
            guard descriptor >= 0 else { throw POSIXError(.EIO) }; defer { close(descriptor) }
            var timeout = timeval(tv_sec: 35, tv_usec: 0)
            setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            var noSignal: Int32 = 1; setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
            var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            let bytes = Array(path.utf8) + [0]
            guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw POSIXError(.ENAMETOOLONG) }
            withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
            guard withUnsafePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            let body = Data((command + "\n").utf8)
            guard body.withUnsafeBytes({ Darwin.send(descriptor, $0.baseAddress!, body.count, 0) }) == body.count else { throw POSIXError(.EIO) }
            var buffer = [UInt8](repeating: 0, count: 256)
            let amount = recv(descriptor, &buffer, buffer.count, 0)
            guard amount > 0 else { throw POSIXError(.ECONNRESET) }
            let text = String(decoding: buffer.prefix(amount), as: UTF8.self)
            guard !text.hasPrefix("error") else { throw RekaControlError.transport(text) }; return text
        }.value
    }
}
