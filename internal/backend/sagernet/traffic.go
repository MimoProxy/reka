package sagernet

// Traffic reports successfully forwarded user-flow payload bytes for this
// process, including already closed connections. Internal DNS/probes are not
// counted as application flows. Counters never decrease within a process.
func (b *Backend) Traffic() (upload, download uint64) {
	return b.trafficUpload.Load(), b.trafficDownload.Load()
}
