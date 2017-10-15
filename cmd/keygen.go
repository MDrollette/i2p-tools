package cmd

import (
	"fmt"

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
				Name:  "tlsHost",
				Usage: "Generate a self-signed TLS certificate and private key for the given host",
			},
		},
	}
}

func keygenAction(c *cli.Context) {
	signerID := c.String("signer")
	tlsHost := c.String("tlsHost")

	if signerID == "" && tlsHost == "" {
		fmt.Println("You must specify either --tlsHost or --signer")
		return
	}

	if signerID != "" {
		if err := createSigningCertificate(signerID); nil != err {
			fmt.Println(err)
			return
		}
	}

	if tlsHost != "" {
		if err := createTLSCertificate(tlsHost); nil != err {
			fmt.Println(err)
			return
		}
	}
}
