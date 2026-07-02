// Package tlsconfig provides built-in TLS for the Go web server.
// Auto-generates a self-signed certificate if none exists.
// Supports custom cert/key upload via web UI.
package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// Config holds TLS file paths and settings.
type Config struct {
	CertPath string
	KeyPath  string
	AutoCert bool // generate self-signed if missing
}

// Load returns a *tls.Config backed by a hot-reloading certificate: when the
// operator uploads a new cert/key from the UI (or regenerates a self-signed
// one), the change is picked up on the next TLS handshake — no UI restart. If
// cert/key are missing and AutoCert is true, a self-signed cert is generated.
func Load(cfg Config) (*tls.Config, error) {
	if cfg.AutoCert {
		if _, err := os.Stat(cfg.CertPath); os.IsNotExist(err) {
			if err := generateSelfSigned(cfg.CertPath, cfg.KeyPath, ""); err != nil {
				return nil, fmt.Errorf("auto-cert: %w", err)
			}
		}
	}

	rl := &Reloader{certPath: cfg.CertPath, keyPath: cfg.KeyPath}
	if _, err := rl.GetCertificate(nil); err != nil { // validate once up front
		return nil, fmt.Errorf("load cert: %w", err)
	}

	return &tls.Config{
		GetCertificate: rl.GetCertificate,
		// TLS 1.3 only: every browser shipped after 2018 supports it
		// (Chrome 70+, Firefox 63+, Safari 12.1+, Edge 79+). Dropping
		// 1.2 closes seven years of accumulated downgrade/cipher attacks
		// and means CipherSuites is now non-configurable (Go uses the
		// TLS 1.3 suite list, which excludes RC4/3DES/CBC entirely).
		MinVersion: tls.VersionTLS13,
	}, nil
}

// Reloader serves the current certificate, reloading from disk whenever the
// cert file's modification time changes.
type Reloader struct {
	certPath, keyPath string
	mu                sync.Mutex
	cached            *tls.Certificate
	mod               time.Time
	size              int64
}

// GetCertificate is the tls.Config.GetCertificate callback. Reloads from disk
// when the cert file's mtime OR size changes (size guards against two writes
// within the same coarse-mtime second).
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fi, err := os.Stat(r.certPath)
	if err == nil && r.cached != nil && fi.ModTime().Equal(r.mod) && fi.Size() == r.size {
		return r.cached, nil
	}
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		if r.cached != nil {
			return r.cached, nil // keep serving the last good cert on a bad swap
		}
		return nil, err
	}
	r.cached = &cert
	if fi != nil {
		r.mod = fi.ModTime()
		r.size = fi.Size()
	}
	return r.cached, nil
}

// InstallPEM validates that certPEM/keyPEM form a usable keypair and, if so,
// atomically writes them to the live cert/key paths (key 0600). A bad pair is
// rejected without touching the live files.
func InstallPEM(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	if err := writeAtomic(certPath, certPEM, 0644); err != nil {
		return err
	}
	if err := writeAtomic(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	return nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// GenerateSelfSignedFor creates a fresh self-signed cert that includes fqdn as
// its CommonName + DNS SAN (in addition to localhost + local IPs). Empty fqdn
// behaves like the default appliance cert. Used by the UI "regenerate" action.
func GenerateSelfSignedFor(certPath, keyPath, fqdn string) error {
	return generateSelfSigned(certPath, keyPath, fqdn)
}

// generateSelfSigned creates a self-signed ECDSA P-256 certificate.
// Valid for 10 years, includes localhost + all local IPs as SANs, plus fqdn
// (CN + DNS SAN) when non-empty.
func generateSelfSigned(certPath, keyPath, fqdn string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()

	cn := "Packet Broker"
	if fqdn != "" {
		cn = fqdn
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Packet Broker"},
			CommonName:   cn,
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// SANs: localhost + all local IPs (+ fqdn)
	tmpl.DNSNames = []string{"localhost"}
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ipnet.IP)
			}
		}
	}
	if h, err := os.Hostname(); err == nil {
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	if fqdn != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, fqdn)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Write cert
	cf, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	// Write key
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	kf, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	kf.Close()

	return nil
}
