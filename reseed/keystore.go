package reseed

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"strings"
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
	return strings.Replace(signer, "@", "_at_", 2) + ".crt"
}
