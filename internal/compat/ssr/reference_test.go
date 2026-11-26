package ssr

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// TestReferenceServer runs the client against an external SSR server. Set
// REKA_SSR_REFERENCE_SERVER to a command that starts a ShadowsocksR server
// from the JSON configuration path appended as its final argument.
func TestReferenceServer(t *testing.T) {
	command := strings.Fields(os.Getenv("REKA_SSR_REFERENCE_SERVER"))
	if len(command) == 0 {
		t.Skip("REKA_SSR_REFERENCE_SERVER is not set")
	}
	tcpEcho, udpEcho := startTCPEcho(t), startUDPEcho(t)
	obfsNames := []string{"plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"}
	protocols := []string{"origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"}
	type pair struct{ method, obfs, protocol string }
	var cases []pair
	for _, o := range obfsNames {
		for _, p := range protocols {
			cases = append(cases, pair{"aes-256-cfb", o, p})
		}
	}
	for _, m := range []string{"none", "rc4-md5", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb"} {
		cases = append(cases, pair{m, "tls1.2_ticket_auth", "auth_chain_a"}, pair{m, "http_simple", "auth_aes128_md5"})
	}
	for _, tc := range cases {
		t.Run(tc.method+"/"+tc.obfs+"/"+tc.protocol, func(t *testing.T) {
			port := startReference(t, command, tc.method, tc.obfs, tc.protocol)
			client, err := New(Config{Server: "127.0.0.1", Port: port, Method: tc.method, Password: "reference-password",
				Obfs: tc.obfs, ObfsParam: "cover.example", Protocol: tc.protocol})
			if err != nil {
				t.Fatal(err)
			}
			t.Run("tcp", func(t *testing.T) { checkTCP(t, client, port, tcpEcho) })
			// SSR obfs applies only to TCP, so UDP is checked once per method and protocol.
			if tc.obfs == "plain" || tc.method != "aes-256-cfb" {
				t.Run("udp", func(t *testing.T) { checkUDP(t, client, port, udpEcho) })
			}
		})
	}
}

func startReference(t *testing.T, command []string, method, obfs, protocol string) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	config, _ := json.Marshal(map[string]any{
		"server": "127.0.0.1", "server_port": port, "password": "reference-password", "method": method,
		"protocol": protocol, "protocol_param": "", "obfs": obfs, "obfs_param": "", "timeout": 60, "udp_timeout": 60,
		"forbidden_ip": "", "fast_open": false, "dns_ipv6": false, "connect_verbose_info": 0, "redirect": "",
		"additional_ports": map[string]any{}, "additional_ports_only": false, "speed_limit_per_con": 0, "speed_limit_per_user": 0,
	})
	path := filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(path, config, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd := exec.Command(command[0], append(command[1:], path)...)
	cmd.Stdout, cmd.Stderr = &output, &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(output.String())
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = conn.Close()
			return uint16(port)
		}
		if time.Now().After(deadline) {
			t.Fatalf("reference server did not start: %v\n%s", err, output.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func checkTCP(t *testing.T, client *Client, port uint16, echo *net.TCPAddr) {
	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	conn, err := client.StreamConn(raw, M.SocksaddrFromNet(echo))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, 37, 1500, 16 * 1024, 200 * 1024} {
		payload := make([]byte, size)
		_, _ = rand.Read(payload)
		errs := make(chan error, 1)
		go func() { _, err := conn.Write(payload); errs <- err }()
		got := make([]byte, size)
		if _, err = io.ReadFull(conn, got); err != nil {
			t.Fatalf("read %d bytes: %v", size, err)
		}
		if err = <-errs; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo of %d bytes differs", size)
		}
	}
}

func checkUDP(t *testing.T, client *Client, port uint16, echo *net.UDPAddr) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := client.PacketConn(raw, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	for _, size := range []int{1, 100, 1200} {
		payload := make([]byte, size)
		_, _ = rand.Read(payload)
		var got []byte
		for attempt := 0; attempt < 5 && got == nil; attempt++ {
			if _, err = conn.WriteTo(payload, echo); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 65535)
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				continue
			}
			if from.String() != echo.String() {
				t.Fatalf("reply from %v, want %v", from, echo)
			}
			got = buffer[:n]
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("UDP echo of %d bytes failed", size)
		}
	}
}

func startTCPEcho(t *testing.T) *net.TCPAddr {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().(*net.TCPAddr)
}

func startUDPEcho(t *testing.T) *net.UDPAddr {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buffer[:n], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}
