package su3

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"strings"
)

func signerCertificate(signer string) (*x509.Certificate, error) {
	certFile := filepath.Base(signerFilename(signer))
	certString, err := ioutil.ReadFile(filepath.Join("./certificates/reseed", certFile))
	if nil != err {
		return nil, err
	}

	certPem, _ := pem.Decode(certString)
	return x509.ParseCertificate(certPem.Bytes)
}

func signerFilename(signer string) string {
	return strings.Replace(signer, "@", "_at_", 2) + ".crt"
}
