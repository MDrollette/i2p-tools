package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/MDrollette/go-i2p/su3"
	"github.com/codegangsta/cli"
)

func NewKeygenCommand() cli.Command {
	return cli.Command{
		Name:   "keygen",
		Usage:  "Generate keys for reseed su3 signing and TLS serving.",
		Action: keygenAction,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "signer",
				Usage: "Your su3 signing ID (ex. something@mail.i2p)",
			},
			cli.StringFlag{
				Name:  "host",
				Usage: "Hostname to use for self-signed TLS certificate",
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

	// generate private key
	fmt.Println("Generating keys. This may take a moment...")
	signerKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalln(err)
	}

	signerCert, err := su3.NewSigningCertificate(signerId, signerKey)

	// save private key
	privFile := strings.Replace(signerId, "@", "_at_", 1) + ".pem"
	if ioutil.WriteFile(privFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signerKey)}), 0600); err != nil {
		log.Fatalln(err)
	}
	fmt.Println("private key saved to:", privFile)

	// save cert
	certFile := strings.Replace(signerId, "@", "_at_", 1) + ".crt"
	if ioutil.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signerCert}), 0755); err != nil {
		log.Fatalln(err)
	}
	fmt.Println("certificate saved to", certFile)
}
