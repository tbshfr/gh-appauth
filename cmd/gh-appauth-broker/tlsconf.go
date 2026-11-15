package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	tlsOff   = "off"
	tlsSelf  = "self"
	tlsFiles = "files"
)

// certSource serves the current certificate and can reload it (SIGHUP).
type certSource struct {
	mu   sync.RWMutex
	cert *tls.Certificate
	load func() (*tls.Certificate, error)
}

func (c *certSource) reload() error {
	cert, err := c.load()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.cert = cert
	c.mu.Unlock()
	return nil
}

func (c *certSource) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert, nil
}

func (c *certSource) fingerprint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return certFingerprint(c.cert.Certificate[0])
}

func (c *certSource) tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: c.get}
}

// certFingerprint is the SHA-256 of the leaf certificate DER, formatted the
// way `openssl x509 -fingerprint -sha256` prints it.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func newFileCertSource(certFile, keyFile string) (*certSource, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("-tls files needs -tls-cert and -tls-key")
	}
	cs := &certSource{load: func() (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		return &c, err
	}}
	return cs, cs.reload()
}

// newSelfCertSource loads the self-signed certificate kept in the database,
// generating one on first use. Pinning clients ignore hostnames, so the
// certificate is only regenerated when it nears expiry or when hosts were
// given explicitly (-tls-hosts) and are not covered; either way clients
// pinning the old fingerprint must re-run setup.
func newSelfCertSource(st *Store, hosts []string, explicitHosts bool) (*certSource, error) {
	cs := &certSource{load: func() (*tls.Certificate, error) {
		certPEM, _ := st.GetSetting("tls_self_cert")
		keyPEM, _ := st.GetSetting("tls_self_key")
		if certPEM != "" && keyPEM != "" {
			c, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
			if err == nil {
				leaf, _ := x509.ParseCertificate(c.Certificate[0])
				if leaf != nil && time.Now().Before(leaf.NotAfter.Add(-24*time.Hour)) && (!explicitHosts || coversHosts(leaf, hosts)) {
					return &c, nil
				}
			}
		}
		certPEM, keyPEM, err := generateSelfSigned(hosts)
		if err != nil {
			return nil, err
		}
		if err := st.SetSetting("tls_self_cert", certPEM); err != nil {
			return nil, err
		}
		if err := st.SetSetting("tls_self_key", keyPEM); err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "gh-appauth-broker: generated new self-signed TLS certificate for %s\n", strings.Join(hosts, ", "))
		c, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		return &c, err
	}}
	return cs, cs.reload()
}

func coversHosts(c *x509.Certificate, hosts []string) bool {
	for _, h := range hosts {
		if c.VerifyHostname(h) != nil {
			return false
		}
	}
	return true
}

// defaultHosts lists names for the self-signed certificate: localhost, the
// hostname and every interface address.
func defaultHosts() []string {
	set := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	if h, err := os.Hostname(); err == nil && h != "" {
		set[h] = true
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				set[ipn.IP.String()] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func generateSelfSigned(hosts []string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "gh-appauth-broker", Organization: []string{"gh-appauth"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})), nil
}
