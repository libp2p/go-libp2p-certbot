package certbot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"

	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/require"
)

func init() {
	certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
}

func TestInitializeFromDomains(t *testing.T) {
	m, err := New(WithDomains("libp2p.io", "ipfs.io", "libp2p.io"))
	require.NoError(t, err)
	defer m.Close()
	require.ElementsMatch(t, m.domains, []string{"ipfs.io", "libp2p.io"})
}

func TestInitializeFromMultiaddrs(t *testing.T) {
	m, err := New(WithAddresses(
		ma.StringCast("/ip4/127.0.0.1/tcp/1234"),
		ma.StringCast("/dns4/libp2p.io/tcp/443"),
		ma.StringCast("/ip6/2001:db8::8a2e:370:7334/udp/1234/quic"),
		ma.StringCast("/dns6/ipfs.io/tcp/443"),
	))
	require.NoError(t, err)
	defer m.Close()
	require.ElementsMatch(t, m.domains, []string{"ipfs.io", "libp2p.io"})
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
