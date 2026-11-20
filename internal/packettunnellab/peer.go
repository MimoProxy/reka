// Package packettunnellab provides a closed test peer for packet-flow tests.
package packettunnellab

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/miekg/dns"
)

const (
	Destination = "203.0.113.42"
	DNSServer   = "203.0.113.53"
	Domain      = "reka.invalid"
	Method      = "aes-128-gcm"
)

type Node struct {
	Server   string `json:"server"`
	Port     uint16 `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

type Fixture struct {
	Node        Node   `json:"node"`
	Destination string `json:"destination"`
	DNSServer   string `json:"dnsServer"`
	Domain      string `json:"domain"`
	TCPPort     uint16 `json:"tcpPort"`
	UDPPort     uint16 `json:"udpPort"`
}

type Peer struct {
	Fixture
	tcp  *net.TCPListener
	udp  *net.UDPConn
	dns  *dns.Server
	node *sagernet.Server
}

func Start(address netip.Addr, port uint16) (_ *Peer, err error) {
	if !address.Is4() || (!address.IsLoopback() && !address.IsPrivate()) {
		return nil, errors.New("test peer requires a loopback or private IPv4 address")
	}
	loopback := net.IPv4(127, 0, 0, 1)
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: loopback})
	if err != nil {
		return nil, err
	}
	peer := &Peer{tcp: tcp}
	defer func() {
		if err != nil {
			peer.Close()
		}
	}()
	peer.udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		return nil, err
	}
	dnsSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		return nil, err
	}
	peer.dns = &dns.Server{PacketConn: dnsSocket, Handler: dns.HandlerFunc(answer)}
	started := make(chan struct{})
	dnsExit := make(chan error, 1)
	peer.dns.NotifyStartedFunc = func() { close(started) }
	go func() { dnsExit <- peer.dns.ActivateAndServe() }()
	select {
	case <-started:
	case err = <-dnsExit:
		return nil, err
	}

	if port == 0 {
		listener, allocErr := net.ListenTCP("tcp4", &net.TCPAddr{IP: address.AsSlice()})
		if allocErr != nil {
			return nil, allocErr
		}
		port = uint16(listener.Addr().(*net.TCPAddr).Port)
		_ = listener.Close()
	}
	secret := make([]byte, 24)
	if _, err = rand.Read(secret); err != nil {
		return nil, err
	}
	password := base64.RawURLEncoding.EncodeToString(secret)
	tcpAddress := tcp.Addr().(*net.TCPAddr).AddrPort()
	udpAddress := peer.udp.LocalAddr().(*net.UDPAddr).AddrPort()
	target := netip.MustParseAddr(Destination)
	targets := map[netip.AddrPort]netip.AddrPort{
		netip.AddrPortFrom(target, tcpAddress.Port()):          tcpAddress,
		netip.AddrPortFrom(target, udpAddress.Port()):          udpAddress,
		netip.AddrPortFrom(netip.MustParseAddr(DNSServer), 53): dnsSocket.LocalAddr().(*net.UDPAddr).AddrPort(),
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	peer.node, err = sagernet.StartShadowsocksTestServer(netip.AddrPortFrom(address, port), Method, password, logger, targets)
	if err != nil {
		return nil, err
	}
	peer.Fixture = Fixture{
		Node:        Node{Server: address.String(), Port: port, Method: Method, Password: password},
		Destination: Destination, DNSServer: DNSServer, Domain: Domain, TCPPort: tcpAddress.Port(), UDPPort: udpAddress.Port(),
	}
	go peer.serveTCP()
	go peer.serveUDP()
	return peer, nil
}

func (p *Peer) Close() {
	if p.node != nil {
		_ = p.node.Close()
	}
	if p.dns != nil {
		_ = p.dns.Shutdown()
	}
	if p.udp != nil {
		_ = p.udp.Close()
	}
	if p.tcp != nil {
		_ = p.tcp.Close()
	}
}

func (p *Peer) serveTCP() {
	for {
		connection, err := p.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(90 * time.Second))
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func (p *Peer) serveUDP() {
	packet := make([]byte, 1500)
	for {
		size, from, err := p.udp.ReadFromUDPAddrPort(packet)
		if err != nil {
			return
		}
		_, _ = p.udp.WriteToUDPAddrPort(packet[:size], from)
	}
}

func answer(writer dns.ResponseWriter, query *dns.Msg) {
	response := new(dns.Msg).SetReply(query)
	if len(query.Question) == 1 && strings.HasSuffix(strings.ToLower(query.Question[0].Name), "."+Domain+".") {
		question := query.Question[0]
		if question.Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
				A:   net.ParseIP(Destination).To4(),
			}}
		}
	} else {
		response.Rcode = dns.RcodeNameError
	}
	_ = writer.WriteMsg(response)
}
