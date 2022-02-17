# go-libp2p-certbot

go-libp2p-certbot is a very thin wrapper around [certmagic](https://github.com/caddyserver/certmagic). It can be used by public libp2p nodes to manage / obtain TLS certificates, which will allow browser nodes to connect directly to them via [WebSockets](https://github.com/libp2p/go-ws-transport).

## Usage

### Manual Certificate Management

This mode allows you to import existing keys and TLS certificates from disc. Certificates are OCSP-stapled, if possible. It's the caller's responsiblity to renew certificates. See the [certmagic documentation](https://pkg.go.dev/github.com/caddyserver/certmagic#readme-can-i-use-some-of-my-own-certificates-while-using-certmagic) for details.
```go
cb, _ := New()
err := cb.AddCert(certFile, keyFile)
tlsConf := cb.GetTLSConfig()
```

### Automatic Certificate Management

ACME is used to obtain certificates for the domains.

Note that in order to complete the ACME challenge, this will temporarily start a TLS listener on port 443.

Using this option means that you agree with LetsEncrypt's legal documents.

```go
import ma "github.com/multiformats/go-multiaddr"


cb, _ := New()
addrs := []ma.Multiaddr{
	ma.StringCast("/ip4/127.0.0.1/tcp/1234"), // multiaddrs without a domain name are ignored
	ma.StringCast("/dns4/example.com/tcp/1234"),
}
cb.AddAddrs(addrs)
// after completion of the ACME challenge, the config will contain a certificate for example.com
tlsConf := cb.GetTLSConfig()
```
