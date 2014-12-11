package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/MDrollette/go-i2p/reseed"
	"github.com/MDrollette/go-i2p/su3"
	"github.com/codegangsta/cli"
)

func NewSu3VerifyCommand() cli.Command {
	return cli.Command{
		Name:        "verify",
		Usage:       "Verify a Su3 file",
		Description: "Verify a Su3 file",
		Action:      su3VerifyAction,
		Flags:       []cli.Flag{},
	}
}

func su3VerifyAction(c *cli.Context) {
	su3File := su3.Su3File{}

	data, err := ioutil.ReadFile(c.Args().Get(0))
	if nil != err {
		panic(err)
	}
	if err := su3File.UnmarshalBinary(data); err != nil {
		panic(err)
	}

	fmt.Println(su3File.String())

	// get the reseeder key
	ks := reseed.KeyStore{Path: "./certificates"}
	cert, err := ks.ReseederCertificate(su3File.SignerId)
	if nil != err {
		panic(err)
	}

	if err := su3File.VerifySignature(cert); nil != err {
		panic(err)
	}

	fmt.Printf("Signature is valid for signer '%s'\n", su3File.SignerId)
}
