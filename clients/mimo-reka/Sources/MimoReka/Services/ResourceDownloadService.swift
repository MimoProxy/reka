import Foundation

struct ResourceDownloadResult: Sendable {
    let file: URL?
    let status: Int
    let etag: String?
    let modified: String?
}

/// URLSession downloads to disk; the delegate cancels oversized responses early.
final class ResourceDownloadService: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ResourceDownloadResult, Error>?
    private var session: URLSession?
    private var result: Result<ResourceDownloadResult, Error>?
    private var cancelled = false
    private var lastPercent = -1
    private let progress: @Sendable (Int64, Int64) async -> Void
    init(progress: @escaping @Sendable (Int64, Int64) async -> Void) { self.progress = progress }
    func download(url: URL, etag: String?, modified: String?) async throws -> ResourceDownloadResult {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if cancelled { lock.unlock(); continuation.resume(throwing: CancellationError()); return }
                self.continuation = continuation
                let config = URLSessionConfiguration.ephemeral
                config.requestCachePolicy = .reloadIgnoringLocalCacheData; config.urlCache = nil
                config.timeoutIntervalForRequest = 60; config.timeoutIntervalForResource = 300
                let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
                let session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
                self.session = session
                var request = URLRequest(url: url)
                request.setValue("Mimo-Reka/0.1.12", forHTTPHeaderField: "User-Agent")
                if let etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
                if let modified { request.setValue(modified, forHTTPHeaderField: "If-Modified-Since") }
                session.downloadTask(with: request).resume()
                lock.unlock()
            }
        } onCancel: { self.cancel() }
    }
    func cancel() {
        lock.lock(); cancelled = true; let session = session; lock.unlock()
        session?.invalidateAndCancel()
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        guard let url = request.url, ["https", "http"].contains(url.scheme ?? ""), url.user == nil, url.password == nil else { completionHandler(nil); return }
        completionHandler(request)
    }
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64, totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        if totalBytesWritten > ResourceLimits.fileBytes || totalBytesExpectedToWrite > ResourceLimits.fileBytes {
            result = .failure(ClientError.message("资源超过 128 MiB，下载已停止。")); downloadTask.cancel(); return
        }
        let percent = totalBytesExpectedToWrite > 0 ? Int(totalBytesWritten * 100 / totalBytesExpectedToWrite) : Int(totalBytesWritten / (1024 * 1024))
        if percent != lastPercent { lastPercent = percent; Task { await progress(totalBytesWritten, totalBytesExpectedToWrite) } }
    }
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        do {
            guard let response = downloadTask.response as? HTTPURLResponse else { throw ClientError.message("资源服务器没有返回 HTTP 响应。") }
            let etag = response.value(forHTTPHeaderField: "ETag"), modified = response.value(forHTTPHeaderField: "Last-Modified")
            if response.statusCode == 304 { result = .success(ResourceDownloadResult(file: nil, status: 304, etag: etag, modified: modified)); return }
            guard response.statusCode == 200 else { throw ClientError.message("资源下载失败：HTTP \(response.statusCode)。") }
            let size = try location.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size > 0, size <= ResourceLimits.fileBytes else { throw ClientError.message("资源为空或超过 128 MiB。") }
            let file = FileManager.default.temporaryDirectory.appendingPathComponent("mimo-reka-resource-" + UUID().uuidString)
            try FileManager.default.moveItem(at: location, to: file)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            result = .success(ResourceDownloadResult(file: file, status: 200, etag: etag, modified: modified))
        } catch { result = .failure(error) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock(); let continuation = continuation; self.continuation = nil; self.session = nil; lock.unlock()
        if let result { continuation?.resume(with: result) }
        else { continuation?.resume(throwing: error ?? ClientError.message("资源下载未完成。")) }
        session.finishTasksAndInvalidate()
    }
}
