//go:build reka_reference

// This isolated test peer links the unmodified pinned mihomo XHTTP server.
// It is excluded from product builds and uses only loopback listeners.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	H "github.com/metacubex/http"
	X "github.com/metacubex/mihomo/transport/xhttp"
	Q "github.com/metacubex/quic-go/http3"
	V "github.com/metacubex/sing-vmess/vless"
	B "github.com/metacubex/sing/common/buf"
	L "github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	T "github.com/metacubex/tls"
)

type request struct {
	Config   json.RawMessage
	Protocol string
	VLESS    bool
	Plain    bool
	Forward  string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	var r request
	if err := json.NewDecoder(os.Stdin).Decode(&r); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(r.Config, &fields); err != nil {
		return err
	}
	normalized := map[string]json.RawMessage{}
	for key, value := range fields {
		normalized[strings.ReplaceAll(key, "-", "")] = value
	}
	encoded, _ := json.Marshal(normalized)
	var config X.Config
	if err := json.Unmarshal(encoded, &config); err != nil {
		return err
	}
	echo := func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }
	if r.Forward != "" {
		address, err := net.ResolveTCPAddr("tcp", r.Forward)
		if err != nil || !address.IP.IsLoopback() {
			return fmt.Errorf("forward target must be loopback")
		}
		echo = func(c net.Conn) {
			defer c.Close()
			up, err := net.DialTimeout("tcp", r.Forward, time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			done := make(chan struct{})
			go func() { _, _ = io.Copy(up, c); _ = up.(*net.TCPConn).CloseWrite(); close(done) }()
			_, _ = io.Copy(c, up)
			_ = c.Close()
			<-done
		}
	}
	if r.VLESS {
		service := V.NewService[int](L.NOP(), echoHandler{})
		service.UpdateUsers([]int{1}, []string{"ca302b35-d67e-437a-bbcb-47773e5bc7d6"}, []string{""})
		echo = func(c net.Conn) { defer c.Close(); _ = service.NewConnection(context.Background(), c, M.Metadata{}) }
	}
	handler, err := X.NewServerHandler(X.ServerOption{Config: config, ConnHandler: echo})
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "xhttp.test"}, DNSNames: []string{"xhttp.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := T.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	tls := &T.Config{Certificates: []T.Certificate{pair}, NextProtos: []string{r.Protocol}}
	if r.Protocol == "h3" {
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		server := &Q.Server{Handler: handler, TLSConfig: tls}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"address": packet.LocalAddr().String(), "certificate": string(certPEM)})
		return server.Serve(packet)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	server := &H.Server{Handler: handler, TLSConfig: tls}
	if r.Plain {
		protocols := new(H.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		server.Protocols = protocols
	}
	if r.Protocol == "mixed" {
		tls.NextProtos = []string{"h2", "http/1.1"}
		packet, err := net.ListenPacket("udp4", listener.Addr().String())
		if err != nil {
			return err
		}
		defer packet.Close()
		quicTLS := tls.Clone()
		downloadCert := *cert
		downloadCert.SerialNumber = big.NewInt(2)
		downloadDER, err := x509.CreateCertificate(rand.Reader, &downloadCert, &downloadCert, &key.PublicKey, key)
		if err != nil {
			return err
		}
		downloadPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: downloadDER})
		downloadPair, err := T.X509KeyPair(downloadPEM, keyPEM)
		if err != nil {
			return err
		}
		quicTLS.Certificates = []T.Certificate{downloadPair}
		certPEM = append(certPEM, downloadPEM...)
		quicTLS.NextProtos = []string{"h3"}
		quicServer := &Q.Server{Handler: handler, TLSConfig: quicTLS}
		defer quicServer.Close()
		go func() { _ = quicServer.Serve(packet) }()
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"address": listener.Addr().String(), "certificate": string(certPEM)})
	if r.Plain {
		return server.Serve(listener)
	}
	return server.ServeTLS(listener, "", "")
}

type echoHandler struct{}

func (echoHandler) NewConnection(_ context.Context, c net.Conn, _ M.Metadata) error {
	defer c.Close()
	_, err := io.Copy(c, c)
	return err
}
func (echoHandler) NewPacketConnection(_ context.Context, c N.PacketConn, _ M.Metadata) error {
	defer c.Close()
	for {
		buffer := B.NewPacket()
		buffer.Resize(256, 0)
		dst, err := c.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return err
		}
		if err = c.WritePacket(buffer, dst); err != nil {
			return err
		}
	}
}
func (echoHandler) NewError(_ context.Context, err error) { fmt.Fprintln(os.Stderr, err) }
