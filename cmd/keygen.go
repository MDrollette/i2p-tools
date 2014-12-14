package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/MDrollette/go-i2p/reseed"
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
				Usage: "Generate a private key and certificate for the given su3 signing ID (ex. something@mail.i2p)",
			},
			cli.StringFlag{
				Name:  "host",
				Usage: "Generate a self-signed TLS certificate and private key for the given host",
			},
		},
	}
}

func keygenAction(c *cli.Context) {
	signerId := c.String("signer")
	host := c.String("host")

	if signerId == "" && host == "" {
		log.Fatalln("You must specify either a --host or a --signer")
	}

	if signerId != "" {
		createSigner(signerId)
	}

	if host != "" {
		createTLSCertificate(host)
	}
}

func createSigner(signerId string) {
	// generate private key
	fmt.Println("Generating signing keys. This may take a minute...")
	signerKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalln(err)
	}

	signerCert, err := su3.NewSigningCertificate(signerId, signerKey)

	// save cert
	certFile := strings.Replace(signerId, "@", "_at_", 1) + ".crt"
	certOut, err := os.Create(certFile)
	if err != nil {
		log.Printf("failed to open %s for writing\n", certFile)
		log.Fatalln(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: signerCert})
	certOut.Close()
	fmt.Println("signing certificate saved to:", certFile)

	// save signing private key
	privFile := strings.Replace(signerId, "@", "_at_", 1) + ".pem"
	keyOut, err := os.OpenFile(privFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("failed to open %s for writing\n", privFile)
		log.Fatalln(err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signerKey)})
	keyOut.Close()
	fmt.Println("signing private key saved to:", privFile)
}

func createTLSCertificate(host string) {
	fmt.Println("Generating TLS keys. This may take a minute...")
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalln("failed to generate TLS private key:", err)
	}

	tlsCert, err := reseed.NewTLSCertificate(host, priv)

	// save the TLS certificate
	certOut, err := os.Create("tls_cert.pem")
	if err != nil {
		log.Fatalln("failed to open tls_cert.pem for writing:", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: tlsCert})
	certOut.Close()
	fmt.Println("TLS certificate saved to: tls_cert.pem")

	// save the TLS private key
	keyOut, err := os.OpenFile("tls_key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalln("failed to open tls_key.pem for writing:", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	fmt.Println("TLS private key saved to: tls_key.pem")
}
