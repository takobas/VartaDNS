// Package certs issues TLS certificates for VartaDNS's encrypted DNS: a
// small local certificate authority and an ACME (Let's Encrypt) client with
// DNS-01 challenges.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func writePair(dir, base string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, base+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, base+".crt"), certPEM, 0o644)
}

// EncodeKey returns the PEM of an EC private key.
func EncodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// CA is a local certificate authority stored in dir/ca.crt and ca.key.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
}

// LoadOrCreateCA loads the CA or creates a new one valid for 10 years.
func LoadOrCreateCA(dir string) (*CA, error) {
	cp, kp := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if c, err := tls.LoadX509KeyPair(cp, kp); err == nil && c.Leaf != nil && c.Leaf.IsCA &&
		time.Until(c.Leaf.NotAfter) > 365*24*time.Hour {
		if k, ok := c.PrivateKey.(*ecdsa.PrivateKey); ok {
			certPEM, _ := os.ReadFile(cp)
			return &CA{Cert: c.Leaf, CertPEM: certPEM, key: k}, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "VartaDNS local CA", Organization: []string{"VartaDNS"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := EncodeKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePair(dir, "ca", certPEM, keyPEM); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

// Issue signs a server certificate for names and ips (about 2 years; the
// CA itself is installed on devices once).
func (ca *CA) Issue(names []string, ips []net.IP) (certPEM, keyPEM []byte, err error) {
	if len(names) == 0 && len(ips) == 0 {
		return nil, nil, errors.New("no names for the certificate")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cn := ""
	if len(names) > 0 {
		cn = names[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPEM = append(certPEM, ca.CertPEM...) // chain
	keyPEM, err = EncodeKey(key)
	return certPEM, keyPEM, err
}

// Save writes a certificate pair as dir/<base>.crt and .key.
func Save(dir, base string, certPEM, keyPEM []byte) error {
	return writePair(dir, base, certPEM, keyPEM)
}
