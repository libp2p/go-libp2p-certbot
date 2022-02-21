package certbot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func init() {
	certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
}

func TestAddMultiaddrs(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	defer m.Close()

	var mx sync.Mutex
	var domains []string
	m.obtainCert = func(_ context.Context, s []string) {
		mx.Lock()
		domains = append(domains, s...)
		mx.Unlock()
	}

	m.AddAddrs([]ma.Multiaddr{
		ma.StringCast("/ip4/127.0.0.1/tcp/1234"),
		ma.StringCast("/dns4/libp2p.io/tcp/443"),
		ma.StringCast("/dns4/libp2p.io/tcp/444"), // duplicate domain, expect to be deduped
		ma.StringCast("/ip6/2001:db8::8a2e:370:7334/udp/1234/quic"),
		ma.StringCast("/dns6/ipfs.io/tcp/443"),
	})
	m.AddAddrs([]ma.Multiaddr{
		ma.StringCast("/dns4/docs.libp2p.io/tcp/443"),
		ma.StringCast("/dns4/libp2p.io/tcp/444"), // duplicate domain, expect to be deduped
	})
	require.Eventually(t, func() bool {
		mx.Lock()
		defer mx.Unlock()
		return len(domains) == 3
	}, time.Second, 10*time.Millisecond)
	require.ElementsMatch(t, domains, []string{"ipfs.io", "libp2p.io", "docs.libp2p.io"})
}

func TestImportKeyAndCert(t *testing.T) {
	dir := t.TempDir()

	generateAndSaveKeyAndCert := func(t *testing.T, filePrefix, dnsName string) (keyPath, certPath string, priv *rsa.PrivateKey) {
		var err error
		priv, err = rsa.GenerateKey(rand.Reader, 1024)
		require.NoError(t, err)
		keyPath = filepath.Join(dir, filePrefix+".pem")
		keyFile, err := os.Create(keyPath)
		require.NoError(t, err)
		defer keyFile.Close()
		require.NoError(t, pem.Encode(keyFile, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		}))

		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{},
			SignatureAlgorithm:    x509.SHA256WithRSA,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour), // valid for an hour
			BasicConstraintsValid: true,
			DNSNames:              []string{dnsName},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
		require.NoError(t, err)
		certPath = filepath.Join(dir, filePrefix+".crt")
		certFile, err := os.Create(certPath)
		require.NoError(t, err)
		defer certFile.Close()
		require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
		return
	}

	key1Path, cert1Path, key1 := generateAndSaveKeyAndCert(t, "key1", "libp2p.io")
	key2Path, cert2Path, key2 := generateAndSaveKeyAndCert(t, "key2", "ipfs.io")

	m, err := New()
	require.NoError(t, err)
	defer m.Close()
	require.NoError(t, m.AddCert(cert1Path, key1Path))
	require.NoError(t, m.AddCert(cert2Path, key2Path))

	libp2pCert, err := m.GetTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "libp2p.io"})
	require.NoError(t, err)
	require.Equal(t, libp2pCert.PrivateKey, key1)
	ipfsCert, err := m.GetTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "ipfs.io"})
	require.NoError(t, err)
	require.Equal(t, ipfsCert.PrivateKey, key2)
}
