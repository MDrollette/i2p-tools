package cmd

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

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

func signerFile(signerID string) string {
	return strings.Replace(signerID, "@", "_at_", 1)
}

func getOrNewSigningCert(signerKey *string, signerID string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(*signerKey); nil != err {
		fmt.Printf("Unable to read signing key '%s'\n", *signerKey)
		fmt.Printf("Would you like to generate a new signing key for %s? (y or n): ", signerID)
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		if []byte(input)[0] != 'y' {
			return nil, fmt.Errorf("A signing key is required")
		}
		if err := createSigningCertificate(signerID); nil != err {
			return nil, err
		}

		*signerKey = signerFile(signerID) + ".pem"
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
		}

		if err := createTLSCertificate(tlsHost); nil != err {
			return err
		}

		*tlsCert = tlsHost + ".crt"
		*tlsKey = tlsHost + ".pem"
	}

	return nil
}

func createSigningCertificate(signerID string) error {
	// generate private key
	fmt.Println("Generating signing keys. This may take a minute...")
	signerKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	signerCert, err := su3.NewSigningCertificate(signerID, signerKey)
	if nil != err {
		return err
	}

	// save cert
	certFile := signerFile(signerID) + ".crt"
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", certFile, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: signerCert})
	certOut.Close()
	fmt.Println("\tSigning certificate saved to:", certFile)

	// save signing private key
	privFile := signerFile(signerID) + ".pem"
	keyOut, err := os.OpenFile(privFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", privFile, err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signerKey)})
	pem.Encode(keyOut, &pem.Block{Type: "CERTIFICATE", Bytes: signerCert})
	keyOut.Close()
	fmt.Println("\tSigning private key saved to:", privFile)

	// CRL
	crlFile := signerFile(signerID) + ".crl"
	crlOut, err := os.OpenFile(crlFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", crlFile, err)
	}
	crlcert, err := x509.ParseCertificate(signerCert)
	if err != nil {
		return fmt.Errorf("Certificate with unknown critical extension was not parsed: %s", err)
	}

	now := time.Now()
	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   crlcert.SerialNumber,
			RevocationTime: now,
		},
	}

	crlBytes, err := crlcert.CreateCRL(rand.Reader, signerKey, revokedCerts, now, now)
	if err != nil {
		return fmt.Errorf("error creating CRL: %s", err)
	}
	_, err = x509.ParseDERCRL(crlBytes)
	if err != nil {
		return fmt.Errorf("error reparsing CRL: %s", err)
	}
	pem.Encode(crlOut, &pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	crlOut.Close()
	fmt.Printf("\tSigning CRL saved to: %s\n", crlFile)

	return nil
}

func createTLSCertificate(host string) error {
	fmt.Println("Generating TLS keys. This may take a minute...")
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
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
	fmt.Printf("\tTLS certificate saved to: %s\n", host+".crt")

	// save the TLS private key
	privFile := host + ".pem"
	keyOut, err := os.OpenFile(privFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", privFile, err)
	}
	secp384r1, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}) // http://www.ietf.org/rfc/rfc5480.txt
	pem.Encode(keyOut, &pem.Block{Type: "EC PARAMETERS", Bytes: secp384r1})
	ecder, err := x509.MarshalECPrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecder})
	pem.Encode(keyOut, &pem.Block{Type: "CERTIFICATE", Bytes: tlsCert})

	keyOut.Close()
	fmt.Printf("\tTLS private key saved to: %s\n", privFile)

	// CRL
	crlFile := host + ".crl"
	crlOut, err := os.OpenFile(crlFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", crlFile, err)
	}
	crlcert, err := x509.ParseCertificate(tlsCert)
	if err != nil {
		return fmt.Errorf("Certificate with unknown critical extension was not parsed: %s", err)
	}

	now := time.Now()
	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   crlcert.SerialNumber,
			RevocationTime: now,
		},
	}

	crlBytes, err := crlcert.CreateCRL(rand.Reader, priv, revokedCerts, now, now)
	if err != nil {
		return fmt.Errorf("error creating CRL: %s", err)
	}
	_, err = x509.ParseDERCRL(crlBytes)
	if err != nil {
		return fmt.Errorf("error reparsing CRL: %s", err)
	}
	pem.Encode(crlOut, &pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	crlOut.Close()
	fmt.Printf("\tTLS CRL saved to: %s\n", crlFile)

	return nil
}
