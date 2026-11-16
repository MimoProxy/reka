package generation

import (
	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"time"
)

func (e *Engine) ProcessTraffic(offset, limit int) api.ProcessTrafficPage {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, total := e.backend.ProcessTraffic(offset, limit)
	page := api.ProcessTrafficPage{SampledAt: time.Now().UTC(), Total: total, Offset: min(offset, total), Limit: limit, Mode: "rule", Supported: e.ProcessLookup(), MaxEntries: sagernet.MaxProcessTrafficEntries, Rows: make([]api.ProcessTrafficRow, 0, len(rows))}
	_, g := e.current()
	if g.eff != nil && g.eff.Process.Mode != "" {
		page.Mode = g.eff.Process.Mode
	}
	for _, row := range rows {
		page.Rows = append(page.Rows, api.ProcessTrafficRow{ID: row.ID, ProcessPath: row.Path, ProcessUID: row.UID, Unknown: row.Unknown, Overflow: row.Overflow, UploadTotal: row.Upload, DownloadTotal: row.Download, ActiveConnections: row.Active, TotalConnections: row.Connections})
	}
	return page
}
