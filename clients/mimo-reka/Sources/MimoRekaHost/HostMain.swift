import Darwin
import Foundation
import CryptoKit

enum HostFailure: LocalizedError {
    case invalid(String)
    var errorDescription: String? { if case .invalid(let text) = self { return text }; return nil }
}

/// An application-specific session host, not an installed service. The root
/// mode only exposes status/stop for one authenticated GUI user and token.
@MainActor
final class RuntimeHost {
    private let child = Process()
    private var sources: [any DispatchSourceProtocol] = []
    private var stopping = false
    private var privileged = false
    private var owner: uid_t = getuid()
    private var token = ""
    private var hostSocket = ""
    private var coreSocket = ""
    private var listener: Int32 = -1
    private var logHandle: FileHandle?
    private var workspaceLock: Int32 = -1
    private var bootstrapArchiveHash: String?
    private var bootstrapDocuments: [String: String]?
    private var ready = false
    private var directoryOwner: uid_t {
        #if MIMO_REKA_HOST_TESTING
        return getuid()
        #else
        return 0
        #endif
    }

    func run(_ arguments: [String]) throws {
        guard let mode = arguments.first else { throw HostFailure.invalid("missing mode") }
        if mode == "--supervise" { try startNormal(Array(arguments.dropFirst())) }
        else if mode == "--privileged" { try startRoot(Array(arguments.dropFirst())) }
        else { throw HostFailure.invalid("unknown mode") }
        for number in [SIGTERM, SIGINT, SIGHUP] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in Task { @MainActor in await self?.stop() } }
            source.resume(); sources.append(source)
        }
        child.terminationHandler = { [weak self] ended in
            Task { @MainActor in
                self?.cleanup()
                exit(ended.terminationStatus)
            }
        }
        try child.run()
        FileHandle.standardError.write(Data("MIMO_REKA_CORE_PID=\(child.processIdentifier)\n".utf8))
        if privileged {
            let path = coreSocket, documents = bootstrapArchiveHash == nil ? bootstrapDocuments : nil
            Task {
                do {
                    try await Task.detached {
                        var failure: Error?
                        for _ in 0..<100 {
                            do { try CoreShutdown.prepare(socketPath: path, documents: documents); return }
                            catch { failure = error; try await Task.sleep(for: .milliseconds(100)) }
                        }
                        throw failure ?? HostFailure.invalid("core initialization timed out")
                    }.value
                    ready = true
                } catch {
                    logHandle?.write(Data("\nMimo Reka host: initialization failed: \(error.localizedDescription)\n".utf8))
                    await stop()
                }
            }
        } else { ready = true }
    }

    private func startNormal(_ arguments: [String]) throws {
        guard geteuid() != 0, [3, 5].contains(arguments.count) else { throw HostFailure.invalid("normal host requires an unprivileged user and explicit profile paths") }
        child.executableURL = URL(fileURLWithPath: arguments[0])
        let profileRoot = URL(fileURLWithPath: arguments[1]).deletingLastPathComponent().path
        let profileID = URL(fileURLWithPath: arguments[1]).lastPathComponent
        var flags = ["-state-root", arguments[1], "-control", "unix://" + arguments[2], "-edit-dir", "-", "-defer-network"]
        var workspaceInfo = stat()
        if lstat(profileRoot, &workspaceInfo) == 0, workspaceInfo.st_mode & S_IFMT == S_IFDIR,
           workspaceInfo.st_uid == getuid(), workspaceInfo.st_mode & 0o022 == 0 {
            flags += ["-profile-root", profileRoot, "-profile-id", profileID]
        }
        if arguments.count == 5 { flags += ["-profile", arguments[3], "-local", arguments[4]] }
        child.arguments = flags
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.standardOutput; child.standardError = FileHandle.standardOutput
        FileHandle.standardInput.readabilityHandler = { [weak self] handle in
            if handle.availableData.isEmpty {
                handle.readabilityHandler = nil
                Task { @MainActor in await self?.stop() }
            }
        }
    }

    private func startRoot(_ arguments: [String]) throws {
        #if MIMO_REKA_HOST_TESTING
        let permittedIdentity = true
        #else
        let permittedIdentity = geteuid() == 0
        #endif
        guard permittedIdentity, [5, 6].contains(arguments.count),
              let uid = UInt32(arguments[0]), uid > 0,
              let parent = Int32(arguments[1]), parent > 1,
              arguments[2].range(of: #"^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"#, options: .regularExpression) != nil,
              UUID(uuidString: arguments[4]) != nil else { throw HostFailure.invalid("invalid privileged session request") }
        privileged = true; owner = uid; token = arguments[4]
        // A process source follows the concrete process instance and receives
        // exit even when the application is killed without a quit callback.
        let parentOwner = try output("/bin/ps", ["-p", String(parent), "-o", "uid="]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard UInt32(parentOwner) == uid else { throw HostFailure.invalid("GUI owner does not match authorization owner") }
        let watchdog = DispatchSource.makeProcessSource(identifier: parent, eventMask: .exit, queue: .main)
        watchdog.setEventHandler { [weak self] in Task { @MainActor in await self?.stop() } }
        watchdog.resume(); sources.append(watchdog)

        let key = arguments[2]
        #if MIMO_REKA_HOST_TESTING
        guard let testing = ProcessInfo.processInfo.environment["MIMO_REKA_HOST_TEST_ROOT"], testing.hasPrefix("/tmp/") else { throw HostFailure.invalid("a temporary test root is required") }
        let base = testing + "/state", runBase = testing + "/run"
        #else
        let base = "/Library/Application Support/MimoReka", runBase = "/var/run/mimo-reka"
        #endif
        for directory in [base, base + "/\(uid)", base + "/\(uid)/\(key)", base + "/\(uid)/\(key)/state"] { try secureDirectory(directory, mode: 0o700) }
        let lockPath = base + "/\(uid)/host-session.lock"
        workspaceLock = open(lockPath, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        var lockInfo = stat()
        guard workspaceLock >= 0, fstat(workspaceLock, &lockInfo) == 0,
              lockInfo.st_mode & S_IFMT == S_IFREG, lockInfo.st_uid == directoryOwner,
              flock(workspaceLock, LOCK_EX | LOCK_NB) == 0 else { throw HostFailure.invalid("another administrator runtime owns this workspace") }
        let state = base + "/\(uid)/\(key)/state"
        let runUser = runBase + "/\(uid)"
        let run = runUser + "/\(key)"
        for directory in [runBase, runUser, run] { try secureDirectory(directory, mode: 0o755) }
        coreSocket = run + "/control.sock"; hostSocket = run + "/host.sock"
        if socketReachable(hostSocket) { throw HostFailure.invalid("this profile already has a running privileged session") }
        _ = unlink(hostSocket)

        var flags = ["-profile-root", base + "/\(uid)", "-profile-id", key, "-profile-state-subdir", "-profile-resume=" + (arguments.count == 6 ? "false" : "true"), "-state-root", state, "-control", "unix://" + coreSocket, "-owner", String(uid), "-edit-dir", "-", "-defer-network"]
        if arguments.count == 6 { bootstrapDocuments = try bootstrap(arguments[5], owner: uid, state: state) }
        if let bootstrapArchiveHash { flags += ["-profile-archive", bootstrapArchiveHash] }
        if bootstrapArchiveHash == nil && !FileManager.default.fileExists(atPath: state + "/active.json") {
            guard let documents = bootstrapDocuments else { throw HostFailure.invalid("the privileged profile has not been initialized") }
            let directory = base + "/\(uid)/\(key)/bootstrap"
            try secureDirectory(directory, mode: 0o700)
            for field in ["profile", "local", "sources", "overlay"] {
                let path = directory + "/" + field + ".yaml"
                try Data(documents[field]!.utf8).write(to: URL(fileURLWithPath: path), options: .atomic)
                guard chmod(path, 0o600) == 0 else { throw posix() }
                flags += ["-" + field, path]
            }
        }
        let log = run + "/core.log"
        let descriptor = open(log, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw posix() }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { close(descriptor); throw HostFailure.invalid("invalid log file") }
        guard fchown(descriptor, uid, gid_t.max) == 0, fchmod(descriptor, 0o600) == 0 else { close(descriptor); throw posix() }
        logHandle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        child.executableURL = URL(fileURLWithPath: arguments[3]); child.arguments = flags
        child.standardInput = FileHandle.nullDevice; child.standardOutput = logHandle; child.standardError = logHandle
        child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": base + "/\(uid)/\(key)"]
        try startControlSocket()
    }

    private func bootstrap(_ path: String, owner: uid_t, state: String) throws -> [String: String] {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else { throw posix() }; defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == owner, info.st_mode & 0o077 == 0, info.st_size > 0, info.st_size <= 64 * 1024 * 1024 else { throw HostFailure.invalid("invalid bootstrap document ownership or size") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        guard let data = try handle.readToEnd(), let bundle = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let documents = bundle["documents"] as? [String: String], let resources = bundle["resources"] as? [String],
              Set(documents.keys) == Set(["profile", "local", "sources", "overlay"]),
              documents.values.allSatisfy({ $0.utf8.count <= 16 * 1024 * 1024 && !$0.contains("secret://") }) else { throw HostFailure.invalid("invalid bootstrap configuration") }
        if let hash = bundle["archive_hash"] as? String {
            guard hash.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil, resources.contains(hash) else { throw HostFailure.invalid("invalid profile archive hash") }
            bootstrapArchiveHash = hash
        }
        let source = URL(fileURLWithPath: path).deletingLastPathComponent().appendingPathComponent("sha256")
        try secureDirectory(state + "/resources", mode: 0o700)
        try secureDirectory(state + "/resources/sha256", mode: 0o700)
        var total: Int64 = 0
        for name in resources {
            guard name.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else { throw HostFailure.invalid("invalid immutable resource name") }
            let input = open(source.appendingPathComponent(name).path, O_RDONLY | O_NOFOLLOW)
            guard input >= 0 else { throw posix() }
            defer { close(input) }
            var resource = stat()
            guard fstat(input, &resource) == 0, resource.st_uid == owner, (resource.st_mode & S_IFMT) == S_IFREG,
                  resource.st_mode & 0o077 == 0, resource.st_size >= 0, resource.st_size <= 128 * 1024 * 1024 else { throw HostFailure.invalid("invalid immutable resource ownership or size") }
            total += resource.st_size
            guard total <= 512 * 1024 * 1024 else { throw HostFailure.invalid("immutable resources exceed migration bound") }
            let inputHandle = FileHandle(fileDescriptor: input, closeOnDealloc: false)
            let bytes = try inputHandle.readToEnd() ?? Data()
            guard SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == name else { throw HostFailure.invalid("immutable resource digest mismatch") }
            let destination = state + "/resources/sha256/" + name
            try bytes.write(to: URL(fileURLWithPath: destination), options: .atomic)
            guard chmod(destination, 0o600) == 0 else { throw posix() }
        }
        return documents
    }

    private func secureDirectory(_ path: String, mode: mode_t) throws {
        if mkdir(path, mode) != 0, errno != EEXIST { throw posix() }
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == directoryOwner, info.st_mode & 0o022 == 0 else { throw HostFailure.invalid("unsafe privileged runtime directory") }
    }

    private func startControlSocket() throws {
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw posix() }
        var address = try unixAddress(hostSocket)
        guard withUnsafePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }) == 0,
              chmod(hostSocket, 0o600) == 0, chown(hostSocket, owner, gid_t.max) == 0,
              listen(listener, 4) == 0 else { throw posix() }
        let source = DispatchSource.makeReadSource(fileDescriptor: listener, queue: .main)
        source.setEventHandler { [weak self] in self?.acceptCommand() }
        source.resume(); sources.append(source)
    }

    private func acceptCommand() {
        let connection = accept(listener, nil, nil)
        guard connection >= 0 else { return }
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(connection, &uid, &gid) == 0, uid == owner || uid == 0 else { close(connection); return }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var noSignal: Int32 = 1
        setsockopt(connection, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        var bytes = [UInt8](repeating: 0, count: 256)
        let amount = recv(connection, &bytes, bytes.count, 0)
        let command = amount > 0 ? String(decoding: bytes.prefix(amount), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) : ""
        if command == "status " + token {
            reply(connection, String(child.isRunning && ready ? child.processIdentifier : 0) + "\n"); close(connection)
        } else if command == "stop " + token {
            // Acknowledgement means the owned shutdown has been requested;
            // the GUI still waits for the foreground authorization task to exit.
            reply(connection, "ok\n"); close(connection)
            Task { @MainActor [weak self] in await self?.stop() }
        } else { reply(connection, "error unauthorized command\n"); close(connection) }
    }

    private func reply(_ descriptor: Int32, _ text: String) {
        let data = Data(text.utf8)
        _ = data.withUnsafeBytes { send(descriptor, $0.baseAddress!, data.count, 0) }
    }

    private func stop() async {
        guard !stopping else { return }; stopping = true
        if privileged && child.isRunning {
            let path = coreSocket
            do { try await Task.detached { try CoreShutdown.prepare(socketPath: path, documents: nil) }.value }
            catch {
                logHandle?.write(Data("\nMimo Reka host: network-off transaction failed; allowing Reka's shutdown journal recovery.\n".utf8))
            }
        }
        if child.isRunning { child.terminate() }
        // Do not force-kill a live network runtime while it is restoring state.
        while child.isRunning { await Task.detached { try? await Task.sleep(for: .milliseconds(100)) }.value }
        cleanup(); exit(0)
    }

    private func cleanup() {
        if listener >= 0 { close(listener); listener = -1 }
        if !hostSocket.isEmpty { _ = unlink(hostSocket) }
        try? logHandle?.close(); logHandle = nil
        if workspaceLock >= 0 { flock(workspaceLock, LOCK_UN); close(workspaceLock); workspaceLock = -1 }
    }
    private func output(_ executable: String, _ arguments: [String]) throws -> String {
        let task = Process(), pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: executable); task.arguments = arguments; task.standardOutput = pipe
        try task.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit()
        guard task.terminationStatus == 0 else { throw HostFailure.invalid("failed to inspect GUI ownership") }
        return String(decoding: data, as: UTF8.self)
    }
}

private func unixAddress(_ path: String) throws -> sockaddr_un {
    var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let bytes = Array(path.utf8) + [0]
    guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw HostFailure.invalid("socket path is too long") }
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }; return address
}
private func posix() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
private func socketReachable(_ path: String) -> Bool {
    let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0, var address = try? unixAddress(path) else { return false }; defer { close(descriptor) }
    return withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0 } }
}

/// The host submits a normal native transaction before shutdown. This keeps
/// network intent off after a GUI crash as well as after a normal quit.
private enum CoreShutdown {
    static func prepare(socketPath: String, documents: [String: String]?) throws {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw posix() }; defer { close(descriptor) }
        var address = try unixAddress(socketPath)
        guard withUnsafePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }) == 0 else { throw posix() }
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var noSignal: Int32 = 1; setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        var sequence = 0
        func call(_ method: String, _ params: [String: Any]) throws -> [String: Any] {
            sequence += 1
            let body = try JSONSerialization.data(withJSONObject: ["id": sequence, "method": method, "params": params], options: [.sortedKeys])
            let size = UInt32(body.count); var frame = Data([UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)]); frame.append(body)
            try frame.withUnsafeBytes { buffer in
                var offset = 0
                while offset < frame.count { let amount = send(descriptor, buffer.baseAddress!.advanced(by: offset), frame.count - offset, 0); guard amount > 0 else { throw posix() }; offset += amount }
            }
            func exact(_ count: Int) throws -> Data {
                var data = Data(count: count)
                try data.withUnsafeMutableBytes { buffer in
                    var offset = 0
                    while offset < count { let amount = recv(descriptor, buffer.baseAddress!.advanced(by: offset), count - offset, 0); guard amount > 0 else { throw posix() }; offset += amount }
                }; return data
            }
            let count = try exact(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard count > 0, count <= 16 * 1024 * 1024,
                  let response = try JSONSerialization.jsonObject(with: exact(Int(count))) as? [String: Any],
                  response["error"] == nil, let result = response["result"] as? [String: Any] else { throw HostFailure.invalid("network recovery request failed") }
            return result
        }
        _ = try call("Hello", ["versions": [1], "client": "mimo-reka-host/0.1"])
        let configuration = try call("GetConfiguration", [:])
        guard let revision = configuration["revision"] else { throw HostFailure.invalid("missing revision") }
        let effective = configuration["effective"] as? [String: Any]
        let network = effective?["network"] as? [String: Any]
        if network?["mode"] as? String == "off", documents == nil { return }
        var change: [String: Any] = ["base_revision": revision, "local_patch": [["op": "set", "path": "/network", "value": ["mode": "off"]]]]
        if let documents { for (field, text) in documents { change[field] = text } }
        let plan = try call("PlanConfiguration", change)
        guard plan["valid"] as? Bool == true, let hash = plan["plan_hash"] as? String else { throw HostFailure.invalid("network recovery plan rejected") }
        change["plan_hash"] = hash; change["operation_id"] = UUID().uuidString; change["source"] = "mimo-reka-host"; change["message"] = "Restore network before host shutdown"
        let result = try call("CommitConfiguration", change)
        guard result["state"] as? String == "committed" else { throw HostFailure.invalid("network recovery commit rejected") }
    }
}

@main
enum HostMain {
    @MainActor static func main() {
        let host = RuntimeHost()
        do {
            try host.run(Array(CommandLine.arguments.dropFirst()))
            withExtendedLifetime(host) { RunLoop.main.run() }
        } catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }
}
