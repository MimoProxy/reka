package control

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/history"
)

func TestRequestHistoryRecordsHTTPKeepAliveWithoutCredentialsOrBodies(t *testing.T) {
	address, _ := startServer(t)
	client, err := Connect(address, "request-history")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Set-Cookie", "fixture=private-cookie")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "private-response-body")
	}))
	defer origin.Close()
	listener := reservedPort(t)
	local := fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\n", listener)
	var commit service.Result
	if err := client.Call("CommitConfiguration", service.CommitRequest{ChangeRequest: service.ChangeRequest{
		BaseRevision: 1, Local: &local,
	}}, &commit); err != nil || commit.State != "committed" {
		t.Fatal(commit, err)
	}
	c, err := net.DialTimeout("tcp", listener, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(c)
	const payload = "private-request-body"
	for _, target := range []string{"/items?token=private-query", "/token/private-path"} {
		_, err = fmt.Fprintf(c, "POST %s%s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\nAuthorization: Bearer private-auth\r\nCookie: fixture=private-cookie\r\nContent-Length: %d\r\n\r\n%s", origin.URL, target, strings.TrimPrefix(origin.URL, "http://"), len(payload), payload)
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil || res.StatusCode != http.StatusCreated || string(got) != "private-response-body" {
			t.Fatal(res.StatusCode, string(got), err)
		}
	}
	_, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin.Listener.Addr(), origin.Listener.Addr())
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatal(res, err)
	}
	_ = c.Close()

	var page history.Page
	if err := client.Call("ListRequestHistory", nil, &page); err != nil || len(page.Rows) != 2 {
		t.Fatal(page, err)
	}
	for i, expected := range []string{"/token/[redacted]", "/items"} {
		data := string(page.Rows[i].Data)
		if strings.Contains(data, "private-") {
			t.Fatal("record retained a raw secret", data)
		}
		var request struct {
			ConnectionID uint64 `json:"connection_id"`
			Status       int    `json:"status_code"`
			RequestBytes int    `json:"request_bytes"`
			TTFB         *int64 `json:"ttfb_ms"`
			Path         string `json:"path"`
		}
		if err := json.Unmarshal(page.Rows[i].Data, &request); err != nil {
			t.Fatal(err)
		}
		if request.ConnectionID == 0 || request.Status != http.StatusCreated ||
			request.RequestBytes != len(payload) || request.Path != expected || request.TTFB == nil {
			t.Fatalf("unexpected record: %+v", request)
		}
	}
}
