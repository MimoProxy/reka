import Foundation

extension AppStore {
    var managedResources: [ManagedResource] { ManagedResource.read(documents) }

    @discardableResult
    func saveResource(_ draft: ManagedResourceDraft, force: Bool = false, quiet: Bool = false) async -> Bool {
        guard isOnline, !resourceUpdates.busyKeys.contains(draft.key), resourceUpdates.busyKeys.isEmpty else { return false }
        let profile = activeProfileID, socket = kernel.socketPath, control = client, session = operations.session
        let previousError = errorMessage
        resourceUpdates.load(profile: profile, home: homeURL)
        resourceUpdates.busyKeys.insert(draft.key); resourceUpdates.progress[draft.key] = "准备资源…"
        var status = resourceUpdates.statuses[draft.key] ?? ResourceUpdateStatus()
        var temporary: URL?
        defer {
            if let temporary { try? FileManager.default.removeItem(at: temporary) }
            resourceUpdates.downloader = nil
            resourceUpdates.busyKeys.remove(draft.key); resourceUpdates.progress.removeValue(forKey: draft.key)
        }
        do {
            _ = try draft.definition(hash: draft.original?.hash ?? "")
            var file = draft.localFile, downloaded: ResourceDownloadResult?
            var url = draft.url.trimmingCharacters(in: .whitespacesAndNewlines)
            if draft.input == "url", url == "********" {
                let config = try await control.call("GetConfiguration", params: ["reveal": .bool(true)])
                let entries = try YAMLDocument.array(config["profile"].stringValue ?? "", key: draft.collection)
                url = entries.first { $0["id"].stringValue == draft.identifier }?["download"]["url"].stringValue ?? ""
            }
            let shouldDownload = draft.input == "url" && (force || draft.original == nil || draft.original?.url != draft.url || draft.original?.fields["format"]?.stringValue != draft.format || (!draft.isDatabase && (draft.original?.fields["behavior"]?.stringValue != draft.behavior || draft.original?.fields["code"]?.stringValue != (draft.code.isEmpty ? nil : draft.code))))
            if shouldDownload {
                guard let address = URL(string: url), ["https", "http"].contains(address.scheme ?? ""), address.host != nil else { throw ClientError.message("资源下载地址无效。") }
                let identity = ManagedResourceState.identity(url: url, hash: draft.original?.hash ?? "")
                let conditional = identity == status.identity
                let downloader = ResourceDownloadService { received, total in
                    await MainActor.run {
                        guard self.activeProfileID == profile else { return }
                        self.resourceUpdates.progress[draft.key] = total > 0 ? "下载 \(received * 100 / total)%" : "下载 \(ByteCountFormatter.string(fromByteCount: received, countStyle: .binary))"
                    }
                }
                resourceUpdates.downloader = downloader
                downloaded = try await downloader.download(url: address, etag: conditional ? status.etag : nil, modified: conditional ? status.modified : nil)
                file = downloaded?.file; temporary = file
                if downloaded?.status == 304 && !conditional { throw ClientError.message("服务器返回 304，但当前资源没有匹配的本地版本。") }
            }
            try Task.checkCancellation()
            guard activeProfileID == profile, kernel.socketPath == socket, operations.session == session, isOnline else { throw CancellationError() }
            var hash = draft.original?.hash ?? ""
            if let file {
                let digest = try ResourceImportService.digest(file: file)
                if digest.hash != hash {
                    resourceUpdates.progress[draft.key] = "上传并校验…"
                    hash = try await ResourceImportService.stage(file: file, client: control) { received, total in
                        await MainActor.run {
                            guard self.activeProfileID == profile else { return }
                            self.resourceUpdates.progress[draft.key] = "上传并校验 \(total == 0 ? 100 : received * 100 / total)%"
                        }
                    }
                }
            }
            guard !hash.isEmpty else { throw ClientError.message("请选择本地文件或输入可下载的资源地址。") }
            let definition = try draft.definition(hash: hash)
            guard activeProfileID == profile, kernel.socketPath == socket, operations.session == session, isOnline else { throw CancellationError() }
            let current = managedResources.first { $0.id == draft.key }
            guard current == draft.original else { throw ClientError.message("资源在下载期间发生变化，请重新打开编辑器后保存。") }
            if quiet && errorMessage != nil { throw CancellationError() }
            if definition != current?.fields {
                let saved = await perform {
                    let config = try await control.call("GetConfiguration")
                    let entries = try YAMLDocument.array(config["profile"].stringValue ?? "", key: draft.collection)
                    let latest = entries.first { $0["id"].stringValue == draft.identifier }
                    guard latest?.objectValue == draft.original?.fields else { throw ClientError.message("资源已被其他操作修改，请重新打开编辑器。") }
                    let exists = latest != nil
                    let operation: JSONValue = .object(["op": .string(exists ? "set" : "insert"), "path": .string("/" + draft.collection + (exists ? "/" + ConfigurationService.escape(draft.identifier) : "")), "value": .object(definition)])
                    let prepared = try await self.configurationService.prepare(["base_revision": config["revision"], "patch": .array([operation])], summary: "更新资源 · " + draft.identifier)
                    _ = try await self.configurationService.commit(prepared)
                }
                guard saved else { throw ClientError.message(errorMessage ?? "客户端正忙，请稍后重试。") }
                if draft.original?.hash != hash { status.updatedAt = Date() }
            }
            if shouldDownload || file != nil { status.checkedAt = Date() }; status.failure = nil
            if let downloaded {
                status.etag = downloaded.etag ?? (downloaded.status == 304 ? status.etag : nil)
                status.modified = downloaded.modified ?? (downloaded.status == 304 ? status.modified : nil)
                status.identity = ManagedResourceState.identity(url: url, hash: hash)
            }
            resourceUpdates.statuses[draft.key] = status
            try resourceUpdates.persist(profile: profile, home: homeURL)
            if !quiet { notice = downloaded?.status == 304 || (draft.original?.hash == hash && force) ? "资源已检查，当前版本无需更新。" : "资源已校验并保存，引用它的规则已生效。" }
            else if draft.original?.hash != hash { notice = "资源“\(draft.identifier)”已自动更新。" }
            return true
        } catch is CancellationError { return false }
        catch {
            guard activeProfileID == profile, kernel.socketPath == socket, operations.session == session else { return false }
            status.checkedAt = Date(); status.failure = error.localizedDescription
            resourceUpdates.statuses[draft.key] = status
            try? resourceUpdates.persist(profile: profile, home: homeURL)
            if quiet { errorMessage = previousError }
            else { errorMessage = (draft.original == nil ? "资源未保存。\n" : "资源未更新，继续使用已保存的版本。\n") + error.localizedDescription }
            return false
        }
    }

    func refreshResourcesIfDue(now: Date = Date()) async {
        guard isOnline, !isBusy, errorMessage == nil, resourceUpdates.busyKeys.isEmpty else { return }
        for resource in managedResources where resource.automatic && !resource.url.isEmpty {
            let checked = resourceUpdates.statuses[resource.id]?.checkedAt ?? .distantPast
            let interval = resourceUpdates.statuses[resource.id]?.failure == nil ? resource.interval : min(resource.interval, 900)
            if now.timeIntervalSince(checked) >= Double(interval) {
                _ = await saveResource(ManagedResourceDraft(resource: resource), force: true, quiet: true)
                return // One resource per poll; downloads never overlap.
            }
        }
    }

    @discardableResult
    func deleteManagedResource(_ resource: ManagedResource, baseRevision: Int) async -> Bool {
        let saved = await previewVisualChange(["base_revision": .number(Double(baseRevision)), "patch": .array([.object(["op": .string("remove"), "path": .string("/" + resource.collection + "/" + ConfigurationService.escape(resource.identifier))])])], summary: "删除资源 · " + resource.identifier, save: true)
        if saved {
            resourceUpdates.statuses.removeValue(forKey: resource.id)
            try? resourceUpdates.persist(profile: activeProfileID, home: homeURL)
        }
        return saved
    }
}
