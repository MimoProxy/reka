package generation

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/script"
)

const (
	// Reka limits event spam from one script and across all scripts.
	scriptNoticeRate   = 10
	scriptNoticeBurst  = 5
	scriptNoticeGlobal = 60

	// Reka bounds notification fields so events remain small.
	scriptNoticeTitleMax = 256
	scriptNoticeBodyMax  = 4 << 10
)

type scriptNoticeBucket struct {
	at     time.Time
	tokens float64
}

type scriptNotifications struct {
	mu      sync.Mutex
	now     func() time.Time
	sink    func(api.ScriptNotification)
	buckets map[string]scriptNoticeBucket
	window  [scriptNoticeGlobal]time.Time
	next    int
	sent    uint64
	dropped uint64
}

func newScriptNotifications() *scriptNotifications {
	return &scriptNotifications{now: time.Now, buckets: make(map[string]scriptNoticeBucket)}
}

// SetScriptNotifier installs the event sink used for script notifications.
func (e *Engine) SetScriptNotifier(sink func(api.ScriptNotification)) {
	if notices := e.scriptNotifications; notices != nil {
		notices.mu.Lock()
		notices.sink = sink
		notices.mu.Unlock()
	}
}

func (n *scriptNotifications) counts() (sent, dropped uint64) {
	if n == nil {
		return 0, 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sent, n.dropped
}

type scriptNotifier struct {
	notices *scriptNotifications
	id      string
	module  string
}

func (n scriptNotifier) Post(note script.Notification) {
	n.notices.post(n.id, n.module, note)
}

func (n *scriptNotifications) post(id, module string, note script.Notification) {
	sink, now := n.admit(id)
	if sink == nil {
		return
	}
	event := api.ScriptNotification{
		ScriptID: truncateScriptNotice(id, scriptNoticeTitleMax),
		Module:   truncateScriptNotice(module, scriptNoticeTitleMax),
		Title:    truncateScriptNotice(note.Title, scriptNoticeTitleMax),
		Subtitle: truncateScriptNotice(note.Subtitle, scriptNoticeTitleMax),
		Body:     truncateScriptNotice(note.Body, scriptNoticeBodyMax),
		Time:     now.UTC(),
	}
	if len(note.Options) > 0 {
		if options, err := json.Marshal(note.Options); err == nil && len(options) <= script.NotificationOptionsMax {
			event.Options = options
		}
	}
	sink(event)
}

func (n *scriptNotifications) admit(id string) (func(api.ScriptNotification), time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.sink == nil {
		return nil, time.Time{}
	}
	now := n.now()
	if oldest := n.window[n.next]; !oldest.IsZero() && now.Sub(oldest) < time.Minute {
		n.dropped++
		return nil, time.Time{}
	}
	bucket, ok := n.buckets[id]
	if ok {
		bucket.tokens = min(scriptNoticeBurst, bucket.tokens+float64(now.Sub(bucket.at))/float64(time.Minute)*scriptNoticeRate)
	} else {
		bucket.tokens = scriptNoticeBurst
	}
	if bucket.tokens < 1 {
		n.dropped++
		return nil, time.Time{}
	}
	// Fully replenished buckets can be recreated on demand. Successful
	// admissions bound how many unique script IDs this map can retain.
	for id, previous := range n.buckets {
		if now.Sub(previous.at) >= time.Minute*scriptNoticeBurst/scriptNoticeRate {
			delete(n.buckets, id)
		}
	}
	n.buckets[id] = scriptNoticeBucket{at: now, tokens: bucket.tokens - 1}
	n.window[n.next] = now
	n.next = (n.next + 1) % scriptNoticeGlobal
	n.sent++
	return n.sink, now
}

func truncateScriptNotice(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	for limit > 0 && !utf8.RuneStart(text[limit]) {
		limit--
	}
	return strings.Clone(text[:limit])
}
