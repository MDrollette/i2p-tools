package reseed

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"time"
)

type KeyStore struct {
	Path string
}

func (ks *KeyStore) ReseederCertificate(signer []byte) (*x509.Certificate, error) {
	certFile := filepath.Base(SignerFilename(string(signer)))
	certString, err := ioutil.ReadFile(filepath.Join(ks.Path, "reseed", certFile))
	if nil != err {
		return nil, err
	}

	certPem, _ := pem.Decode(certString)
	return x509.ParseCertificate(certPem.Bytes)
}

func SignerFilename(signer string) string {
	return strings.Replace(signer, "@", "_at_", 1) + ".crt"
}

func NewTLSCertificate(host string, priv *ecdsa.PrivateKey) ([]byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(2 * 365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"I2P Anonymous Network"},
			OrganizationalUnit: []string{"I2P"},
			Locality:           []string{"XX"},
			StreetAddress:      []string{"XX"},
			Country:            []string{"XX"},
			CommonName:         host,
		},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: x509.ECDSAWithSHA256,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}
