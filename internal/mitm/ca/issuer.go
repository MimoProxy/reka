package ca

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Apple limits publicly trusted TLS leaves to 398 days, and the CA/B Forum
// is phasing in a 47-day limit. In-memory leaves can be short-lived at little cost.
const defaultValidity = 7 * 24 * time.Hour

// IssuerOptions sets the cache size and leaf validity; zero values use defaults.
type IssuerOptions struct {
	CacheSize int
	Validity  time.Duration
	Now       func() time.Time
}

// Issuer signs leaf certificates and keeps them in a per-host LRU cache.
// Concurrent requests for one host share a single signing.
type Issuer struct {
	authority *Authority
	cacheSize int
	validity  time.Duration
	now       func() time.Time

	mu       sync.Mutex
	entries  map[string]*list.Element
	lru      list.List
	inflight map[string]*issuance
	epoch    uint64
}

type cacheEntry struct {
	host string
	cert *tls.Certificate
}

type issuance struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

var liveIssuers = struct {
	sync.Mutex
	issuers map[*Issuer]struct{}
}{issuers: make(map[*Issuer]struct{})}

// NewIssuer returns an issuer registered for PurgeAll.
func NewIssuer(a *Authority, opts IssuerOptions) *Issuer {
	if opts.CacheSize <= 0 {
		opts.CacheSize = DefaultCacheSize
	}
	if opts.Validity <= 0 {
		opts.Validity = defaultValidity
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	i := &Issuer{
		authority: a,
		cacheSize: opts.CacheSize,
		validity:  opts.Validity,
		now:       opts.Now,
		entries:   make(map[string]*list.Element),
		inflight:  make(map[string]*issuance),
	}
	liveIssuers.Lock()
	liveIssuers.issuers[i] = struct{}{}
	liveIssuers.Unlock()
	return i
}

// Close unregisters the issuer from memory-pressure handling. The relay owner
// calls Close when shutting down the runtime that owns this issuer.
func (i *Issuer) Close() {
	liveIssuers.Lock()
	delete(liveIssuers.issuers, i)
	liveIssuers.Unlock()
}

// PurgeAll empties the caches of all live issuers, on memory pressure.
func PurgeAll() {
	liveIssuers.Lock()
	defer liveIssuers.Unlock()
	for issuer := range liveIssuers.issuers {
		issuer.Purge()
	}
}

// Purge empties the cache.
func (i *Issuer) Purge() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.entries = make(map[string]*list.Element)
	i.lru.Init()
	// An issuance started before the purge must not repopulate the cache.
	i.epoch++
}

// Len is the number of cached leaves.
func (i *Issuer) Len() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lru.Len()
}

// Certificate returns a shared certificate that callers must not modify.
func (i *Issuer) Certificate(host string) (*tls.Certificate, error) {
	host, ip, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	now := i.now()
	i.mu.Lock()
	if element := i.entries[host]; element != nil {
		cert := element.Value.(cacheEntry).cert
		remaining := cert.Leaf.NotAfter.Sub(now)
		if !now.Before(cert.Leaf.NotBefore) && remaining > 0 && remaining >= i.validity/4 {
			i.lru.MoveToFront(element)
			i.mu.Unlock()
			return cert, nil
		}
		i.lru.Remove(element)
		delete(i.entries, host)
	}
	if pending := i.inflight[host]; pending != nil {
		i.mu.Unlock()
		<-pending.done
		return pending.cert, pending.err
	}
	pending := &issuance{done: make(chan struct{})}
	i.inflight[host] = pending
	epoch := i.epoch
	i.mu.Unlock()

	cert, err := i.authority.issue(host, ip, now, now.Add(i.validity))

	i.mu.Lock()
	defer i.mu.Unlock()
	if err == nil {
		pending.cert = &cert
		if epoch == i.epoch {
			i.entries[host] = i.lru.PushFront(cacheEntry{host: host, cert: &cert})
			if i.lru.Len() > i.cacheSize {
				last := i.lru.Back()
				delete(i.entries, last.Value.(cacheEntry).host)
				i.lru.Remove(last)
			}
		}
	}
	pending.err = err
	delete(i.inflight, host)
	close(pending.done)
	return pending.cert, pending.err
}

// GetCertificate implements tls.Config.GetCertificate using the SNI.
func (i *Issuer) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil || hello.ServerName == "" {
		return nil, errors.New("TLS server name is missing")
	}
	return i.Certificate(hello.ServerName)
}

// Issue signs a one-time certificate for a session with a fixed expiration.
func (a *Authority) Issue(host string, notAfter time.Time) (tls.Certificate, error) {
	host, ip, err := normalizeHost(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	return a.issue(host, ip, time.Now(), notAfter)
}

func (a *Authority) issue(host string, ip netip.Addr, now, notAfter time.Time) (tls.Certificate, error) {
	if now.Before(a.cert.NotBefore) {
		return tls.Certificate{}, errors.New("CA certificate is not yet valid")
	}
	if now.After(a.cert.NotAfter) {
		return tls.Certificate{}, errors.New("CA certificate has expired")
	}
	if notAfter.After(a.cert.NotAfter) {
		notAfter = a.cert.NotAfter
	}
	if !notAfter.Truncate(time.Second).After(now) {
		return tls.Certificate{}, errors.New("TLS certificate expiration must be in the future")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, errors.New("could not generate TLS certificate key")
	}
	template := &x509.Certificate{
		SerialNumber:   newSerialNumber(),
		Subject:        pkix.Name{CommonName: host},
		NotBefore:      now.Add(-clockSkew),
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: a.cert.SubjectKeyId,
	}
	if ip.IsValid() {
		template.IPAddresses = []net.IP{net.IP(ip.AsSlice())}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, key.Public(), a.signer)
	if err != nil {
		return tls.Certificate{}, errors.New("could not create TLS certificate")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, errors.New("could not parse generated TLS certificate")
	}
	return tls.Certificate{
		Certificate: [][]byte{der, a.CertificateDER()},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func normalizeHost(host string) (string, netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", netip.Addr{}, errors.New("TLS certificate host is missing")
	}
	ipHost := host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		ipHost = host[1 : len(host)-1]
	}
	if ip, err := netip.ParseAddr(ipHost); err == nil {
		ip = ip.WithZone("").Unmap()
		return ip.String(), ip, nil
	}
	return host, netip.Addr{}, nil
}
