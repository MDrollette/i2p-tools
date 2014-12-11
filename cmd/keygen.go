package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/MDrollette/go-i2p/reseed"
	"github.com/codegangsta/cli"
)

func NewKeygenCommand() cli.Command {
	return cli.Command{
		Name:        "keygen",
		Usage:       "Generate keys for reseed SU3 signing",
		Description: "Generate keys for reseed SU3 signing",
		Action:      keygenAction,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "signer",
				Usage: "Your SU3 signing ID (your email address)",
			},
		},
	}
}

func keygenAction(c *cli.Context) {
	signerId := c.String("signer")
	if signerId == "" {
		fmt.Println("--signer is required")
		return
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:         true,
		SubjectKeyId: []byte(signerId),
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"I2P Anonymous Network"},
			OrganizationalUnit: []string{"I2P"},
			Locality:           []string{"XX"},
			StreetAddress:      []string{"XX"},
			Country:            []string{"XX"},
			CommonName:         signerId,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	// generate private key
	fmt.Println("Generating keys. This may take a moment...")
	privatekey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalln(err)
	}

	publickey := &privatekey.PublicKey

	// create a self-signed certificate. template = parent
	var parent = template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, privatekey)
	if err != nil {
		log.Fatalln(err)
	}

	// save private key
	pemfile, err := os.Create("reseed_private.pem")
	if err != nil {
		log.Fatalf("failed to open reseed_cert.pem for writing: %s", err)
	}
	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}
	pem.Encode(pemfile, pemkey)
	pemfile.Close()
	fmt.Println("private key saved to reseed_private.pem")

	// save cert
	filename := reseed.SignerFilename(signerId)
	certOut, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", filename, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	certOut.Close()
	fmt.Println("certificate saved to", filename)
}
