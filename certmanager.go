package certbot

import (
	"context"
	"crypto/tls"
	"errors"
	"sort"
	"sync"

	"github.com/caddyserver/certmagic"
	logging "github.com/ipfs/go-log/v2"
	ma "github.com/multiformats/go-multiaddr"
)

var log = logging.Logger("certbot")

var errDomainsAlreadySet = errors.New("domains already set")

func sortAndUnique(slice []string) []string {
	sort.Strings(slice)
	var index int
	for i, s := range slice {
		if i == 0 || slice[i-1] != s {
			slice[index] = s
			index++
		}
	}
	return slice[:index]
}

type Option func(*CertManager) error

// WithDomains sets a list of domains that certificates will be obtained for.
// It cannot be used with WithAddresses.
func WithDomains(domains ...string) Option {
	return func(m *CertManager) error {
		if len(m.domains) > 0 {
			return errDomainsAlreadySet
		}
		m.domains = make([]string, len(domains))
		copy(m.domains, domains)
		m.domains = sortAndUnique(m.domains)
		return nil
	}
}

var (
	dns4Protocol = ma.ProtocolWithCode(ma.P_DNS4)
	dns6Protocol = ma.ProtocolWithCode(ma.P_DNS6)
	dnsProtocol  = ma.ProtocolWithCode(ma.P_DNS)
)

// WithAddresses extracts the domains that certificates will be obtained for from a list of multiaddrs.
// Non-DNS multiaddrs are ignored, and results are deduplicated.
// It cannot be used with WithDomains.
func WithAddresses(addrs ...ma.Multiaddr) Option {
	return func(m *CertManager) error {
		if len(m.domains) > 0 {
			return errDomainsAlreadySet
		}
		for _, addr := range addrs {
			first, _ := ma.SplitFirst(addr)
			switch first.Protocol().Code {
			// TODO: handle dnsaddr addresses
			case dns4Protocol.Code, dns6Protocol.Code, dnsProtocol.Code:
				m.domains = append(m.domains, first.Value())
			}
		}
		m.domains = sortAndUnique(m.domains)
		return nil
	}
}

type CertManager struct {
	ctx       context.Context
	ctxCancel context.CancelFunc
	refCount  sync.WaitGroup

	certmagicCfg *certmagic.Config

	domains []string
}

// New creates a new CertManager.
// Using the ACME functionality in this package means that
// you've read and agree to your CA's legal documents.
func New(opts ...Option) (*CertManager, error) {
	m := &CertManager{
		certmagicCfg: certmagic.NewDefault(),
	}
	m.ctx, m.ctxCancel = context.WithCancel(context.Background())

	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}

	m.refCount.Add(1)
	go m.background()
	return m, nil
}

func (m *CertManager) background() {
	defer m.refCount.Done()

	for _, domain := range m.domains {
		// Call ManageSync for every domain separately.
		// Otherwise, a single failing domain will abort certificate retrieval for _all_ domains.
		if err := m.certmagicCfg.ManageSync(m.ctx, []string{domain}); err != nil {
			log.Infof("managing certificate for %s failed: %s", domain, err)
		}
		log.Debugf("successfully obtained / renewed certificate for %s", domain)

		select {
		case <-m.ctx.Done():
			return
		default:
		}
	}
}

// AddCert adds a certificate from a file on disk.
// It's the caller's responsibility to deal with certificate renewal.
// OCSP stapling is performed, if possible.
// See https://pkg.go.dev/github.com/caddyserver/certmagic#readme-can-i-use-some-of-my-own-certificates-while-using-certmagic for details.
func (m *CertManager) AddCert(certFile, keyFile string) error {
	return m.certmagicCfg.CacheUnmanagedCertificatePEMFile(certFile, keyFile, nil)
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
