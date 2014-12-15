package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"strings"
)

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	privPem, err := ioutil.ReadFile(path)
	if nil != err {
		return nil, err
	}

	privDer, _ := pem.Decode(privPem)
	privKey, err := x509.ParsePKCS1PrivateKey(privDer.Bytes)
	if nil != err {
		return nil, err
	}

	return privKey, nil
}

func signerFile(signerId string) string {
	return strings.Replace(signerId, "@", "_at_", 1)
}
