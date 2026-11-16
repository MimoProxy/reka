import Foundation

extension AppStore {
    /// The durable kernel cursor wins over a stale GUI selection after a crash.
    func synchronizeProfileContext() async throws {
        let control = RekaControlClient(socketPath: kernel.socketPath)
        let state = try await control.call("GetProfileState")
        guard state["enabled"].boolValue == true, let key = state["profile_id"].stringValue,
              let id = UUID(uuidString: key), profiles.contains(where: { $0.id == id }),
              let epoch = state["profile_epoch"].intValue, epoch > 0 else {
            throw ClientError.message("内核的当前配置不在本地索引中，原始档案已保留。")
        }
        activeProfileID = id; profileEpoch = epoch; kernel.adoptProfile(id)
        rebuildController()
        catalog.activeProfileID = id
        if kernel.isPrivileged, let index = catalog.profiles.firstIndex(where: { $0.id == id }) { catalog.profiles[index].privileged = true }
        profiles = catalog.profiles
        try catalog.save(to: homeURL)
    }

    func promoteCurrentProfile() async throws {
        let reveal = try await client.call("GetConfiguration", params: ["reveal": .bool(true)])
        resourceUpdates.downloader?.cancel(); operations.reset()
        do { try await kernel.promote(configuration: reveal) }
        catch {
            // Cancelled authorization resumes the original workspace/context.
            if kernel.isRunning { try? await synchronizeProfileContext() }
            throw error
        }
        try await synchronizeProfileContext()
        startedAt = Date(); snapshot = .null
        capabilities = try await client.call("GetCapabilities")
        try await loadSnapshot(force: true)
    }

    private func installInactiveProfileIfNeeded(_ id: UUID) async throws {
        guard kernel.isPrivileged else { return }
        let key = id.uuidString.lowercased()
        let state = try await client.call("GetProfileState", params: ["profile_id": .string(key)])
        guard state["target_exists"].boolValue != true else { return }
        let root = Self.profileDirectory(root: homeURL, id: id)
        guard let archive = try await Task.detached(operation: { try ProfileArchiveService.prepare(root: root) }).value else { return }
        defer { try? FileManager.default.removeItem(at: archive.file) }
        for resource in archive.resources {
            let hash = try await ResourceImportService.stage(file: resource.file, client: client, profileID: key)
            guard hash == resource.hash else { throw ClientError.message("迁移资源摘要不一致，未切换配置。") }
        }
        let hash = try await ResourceImportService.stage(file: archive.file, client: client)
        _ = try await client.call("InstallProfile", params: ["profile_id": .string(key), "archive_hash": .string(hash)])
        if let index = catalog.profiles.firstIndex(where: { $0.id == id }) { catalog.profiles[index].privileged = true }
        profiles = catalog.profiles
        try catalog.save(to: homeURL)
    }

    func switchProfile(_ id: UUID) async {
        guard !isBusy, id != activeProfileID, profiles.contains(where: { $0.id == id }) else { return }
        isBusy = true; errorMessage = nil
        defer { isBusy = false }
        let previous = activeProfileID
        var committed = false
        var submitted = false
        var decisionKnown = true
        do {
            while refreshing { try await Task.sleep(for: .milliseconds(50)) }
            if !kernel.isRunning { try await startCurrentRuntime() }
            if activeProfileID == id { return }
            resourceUpdates.downloader?.cancel(); operations.reset()
            if profiles.first(where: { $0.id == id })?.privileged == true, !kernel.isPrivileged {
                // Crossing the privilege boundary requires one authorization;
                // all following profile switches reuse this supervised process.
                try await promoteCurrentProfile()
            }
            try await installInactiveProfileIfNeeded(id)
            let state = try await client.call("GetProfileState", params: ["profile_id": .string(id.uuidString.lowercased())])
            let operation = UUID().uuidString
            let params: [String: JSONValue] = [
                "profile_id": .string(id.uuidString.lowercased()), "base_profile": state["profile_id"],
                "base_epoch": state["profile_epoch"], "base_revision": state["revision"],
                "operation_id": .string(operation), "preserve_network": .bool(true),
                "initial_profile": .string(KernelProcess.starterProfile(networkMode: networkMode))
            ]
            // Persist intent before native commit; native cursor resolves the
            // response-loss/crash window on the next launch.
            catalog.activeProfileID = id
            if kernel.isPrivileged, let index = catalog.profiles.firstIndex(where: { $0.id == id }) { catalog.profiles[index].privileged = true }
            try catalog.save(to: homeURL)
            let switching = RekaControlClient(socketPath: kernel.socketPath, timeout: 120, profileID: activeProfileID.uuidString.lowercased(), profileEpoch: profileEpoch)
            let result: JSONValue
            submitted = true; decisionKnown = false
            do { result = try await switching.call("SwitchProfile", params: params) }
            catch {
                let probe = RekaControlClient(socketPath: kernel.socketPath, timeout: 120)
                if let recorded = try? await probe.call("GetProfileSwitchOperation", params: ["operation_id": .string(operation)]), recorded["state"].stringValue != "pending" {
                    result = recorded
                } else {
                    // Exactly the same operation ID is safe to retry; the
                    // kernel serializes and returns its durable decision.
                    result = try await probe.call("SwitchProfile", params: params)
                }
            }
            decisionKnown = result["state"].stringValue != "pending"
            guard result["state"].stringValue == "committed" else {
                throw ClientError.message(result["error"]["message"].stringValue ?? "内核拒绝切换，原配置继续运行。")
            }
            committed = true
            try await synchronizeProfileContext()
            snapshot = .null; preparedChange = nil; pendingSourceName = nil; editingLayer = nil
            _ = try await configurationService.recoverPendingForStartup()
            try await loadSnapshot(force: true)
            startupPhase = "就绪 · 已原子切换配置"
            notice = "已切换配置，内核未重启，保留当前网络接管模式。"
        } catch {
            let failure = error.localizedDescription
            if kernel.isRunning {
                do { try await synchronizeProfileContext(); committed = activeProfileID == id; decisionKnown = true }
                catch { /* Retain the durable intent when the decision is temporarily unreachable. */ }
            }
            if submitted && !decisionKnown {
                isOnline = false
                errorMessage = "切换结果暂时无法确认，已保留切换记录。请恢复连接后重新启动客户端：\(failure)"
                return
            }
            if !committed, activeProfileID == previous {
                catalog.activeProfileID = previous; try? catalog.save(to: homeURL)
                errorMessage = "切换失败，原配置继续运行：\(failure)"
            } else { errorMessage = "配置切换结果需要重新同步：\(failure)" }
            if kernel.isRunning { try? await loadSnapshot(force: true) }
        }
    }
}
