package cmd

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/MDrollette/i2p-tools/reseed"
	"github.com/MDrollette/i2p-tools/su3"
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

func getOrNewSigningCert(signerKey *string, signerId string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(*signerKey); nil != err {
		fmt.Printf("Unable to read signing key '%s'\n", *signerKey)
		fmt.Printf("Would you like to generate a new signing key for %s? (y or n): ", signerId)
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		if []byte(input)[0] != 'y' {
			return nil, fmt.Errorf("A signing key is required")
		} else {
			if err := createSigningCertificate(signerId); nil != err {
				return nil, err
			}

			*signerKey = signerFile(signerId) + ".pem"
		}
	}

	return loadPrivateKey(*signerKey)
}

func checkOrNewTLSCert(tlsHost string, tlsCert, tlsKey *string) error {
	_, certErr := os.Stat(*tlsCert)
	_, keyErr := os.Stat(*tlsKey)
	if certErr != nil || keyErr != nil {
		if certErr != nil {
			fmt.Printf("Unable to read TLS certificate '%s'\n", *tlsCert)
		}
		if keyErr != nil {
			fmt.Printf("Unable to read TLS key '%s'\n", *tlsKey)
		}

		fmt.Printf("Would you like to generate a new self-signed certificate for '%s'? (y or n): ", tlsHost)
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		if []byte(input)[0] != 'y' {
			fmt.Println("Continuing without TLS")
			return nil
		} else {
			if err := createTLSCertificate(tlsHost); nil != err {
				return err
			}

			*tlsCert = tlsHost + ".crt"
			*tlsKey = tlsHost + ".pem"
		}
	}

	return nil
}

func createSigningCertificate(signerId string) error {
	// generate private key
	fmt.Println("Generating signing keys. This may take a minute...")
	signerKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	signerCert, err := su3.NewSigningCertificate(signerId, signerKey)
	if nil != err {
		return err
	}

	// save cert
	certFile := signerFile(signerId) + ".crt"
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s\n", certFile, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: signerCert})
	certOut.Close()
	fmt.Println("signing certificate saved to:", certFile)

	// save signing private key
	privFile := signerFile(signerId) + ".pem"
	keyOut, err := os.OpenFile(privFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s\n", privFile, err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signerKey)})
	keyOut.Close()
	fmt.Println("signing private key saved to:", privFile)

	return nil
}

func createTLSCertificate(host string) error {
	fmt.Println("Generating TLS keys. This may take a minute...")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate TLS private key:", err)
	}

	tlsCert, err := reseed.NewTLSCertificate(host, priv)
	if nil != err {
		return err
	}

	// save the TLS certificate
	certOut, err := os.Create(host + ".crt")
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", host+".crt", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: tlsCert})
	certOut.Close()
	fmt.Printf("TLS certificate saved to: %s\n", host+".crt")

	// save the TLS private key
	keyOut, err := os.OpenFile(host+".pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", host+".pem", err)
	}
	derBytes, err := x509.MarshalECPrivateKey(priv)
	if nil != err {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
	keyOut.Close()
	fmt.Printf("TLS private key saved to: %s\n", host+".pem")

	return nil
}
