package certbot

import (
	"context"
	"crypto/tls"
	"os"
	"sync"

	"github.com/caddyserver/certmagic"
	logging "github.com/ipfs/go-log/v2"
	ma "github.com/multiformats/go-multiaddr"
)

var log = logging.Logger("certbot")

type config struct {
	httpPort, tlsPort int
}

type Option func(*config) error

// WithHTTPPort sets an alternate port to use for the ACME HTTP challenge.
func WithHTTPPort(port int) Option {
	return func(c *config) error {
		c.httpPort = port
		return nil
	}
}

// WithTLSPort sets an alternate port to use for the ACME TLS ALPN challenge.
func WithTLSPort(port int) Option {
	return func(c *config) error {
		c.tlsPort = port
		return nil
	}
}

var (
	dns4Protocol = ma.ProtocolWithCode(ma.P_DNS4)
	dns6Protocol = ma.ProtocolWithCode(ma.P_DNS6)
	dnsProtocol  = ma.ProtocolWithCode(ma.P_DNS)
)

type CertManager struct {
	ctx       context.Context
	ctxCancel context.CancelFunc
	refCount  sync.WaitGroup

	certmagicCfg *certmagic.Config
	// So we can mock the call to certmagicCfg.ManageAsync in tests.
	obtainCert func(context.Context, []string)

	mutex    sync.Mutex
	queue    []string
	incoming chan struct{}
}

// New creates a new CertManager.
// Using the ACME functionality in this package means that
// you've read and agree to your CA's legal documents.
func New(opts ...Option) (*CertManager, error) {
	var conf config
	for _, opt := range opts {
		if err := opt(&conf); err != nil {
			return nil, err
		}
	}
	cfg := certmagic.NewDefault()
	tmpl := certmagic.ACMEManager{
		AltHTTPPort:    conf.httpPort,
		AltTLSALPNPort: conf.tlsPort,
		Agreed:         true,
	}
	if os.Getenv("LIBP2P_CERTBOT_STAGING") != "" {
		tmpl.CA = certmagic.LetsEncryptStagingCA
	}
	acmeManager := certmagic.NewACMEManager(cfg, tmpl)
	cfg.Issuers = []certmagic.Issuer{acmeManager}

	m := &CertManager{
		certmagicCfg: cfg,
		incoming:     make(chan struct{}, 1),
	}
	m.ctx, m.ctxCancel = context.WithCancel(context.Background())
	m.obtainCert = func(ctx context.Context, domains []string) {
		if err := m.certmagicCfg.ManageAsync(ctx, domains); err != nil {
			log.Debugf("failed to async manage certificate for domain: %v", domains)
		}
	}

	m.refCount.Add(1)
	go m.background()
	return m, nil
}

func (m *CertManager) background() {
	defer m.refCount.Done()

	domains := make(map[string]struct{})
	for {
		select {
		case <-m.incoming:
		case <-m.ctx.Done():
			return
		}

		m.mutex.Lock()
		queue := m.queue
		m.queue = nil
		m.mutex.Unlock()

		var newDomains []string
		for _, domain := range queue {
			// We already tried obtaining a certificate for this domain.
			if _, ok := domains[domain]; ok {
				continue
			}
			newDomains = append(newDomains, domain)
			domains[domain] = struct{}{}
		}
		if len(newDomains) == 0 {
			continue
		}
		m.obtainCert(m.ctx, newDomains)
		log.Debugf("obtaining certificates for %v", newDomains)
	}
}

// AddCert adds a certificate from a file on disk.
// It's the caller's responsibility to deal with certificate renewal.
// OCSP stapling is performed, if possible.
// See https://pkg.go.dev/github.com/caddyserver/certmagic#readme-can-i-use-some-of-my-own-certificates-while-using-certmagic for details.
func (m *CertManager) AddCert(certFile, keyFile string) error {
	return m.certmagicCfg.CacheUnmanagedCertificatePEMFile(certFile, keyFile, nil)
}

func (m *CertManager) AddAddrs(addrs []ma.Multiaddr) {
	var added bool
	m.mutex.Lock()
	for _, addr := range addrs {
		first, _ := ma.SplitFirst(addr)
		switch first.Protocol().Code {
		// TODO: handle dnsaddr addresses
		case dns4Protocol.Code, dns6Protocol.Code, dnsProtocol.Code:
			m.queue = append(m.queue, first.Value())
			added = true
		}
	}
	m.mutex.Unlock()
	if !added {
		return
	}
	select {
	case m.incoming <- struct{}{}:
	default:
	}
}

// GetTLSConfig returns a tls.Config that can be use for a TLS listener.
func (m *CertManager) GetTLSConfig() *tls.Config {
	conf := m.certmagicCfg.TLSConfig().Clone()
	conf.NextProtos = nil // remove the ACME ALPN
	return conf
}

func (m *CertManager) Close() error {
	m.ctxCancel()
	m.refCount.Wait()
	return nil
}
