package cmd

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/MDrollette/go-i2p/reseed"
	"github.com/codegangsta/cli"
)

func NewSu3Command() cli.Command {
	return cli.Command{
		Name:        "su3",
		Usage:       "Do SU3 things",
		Description: "Do SU3 things",
		Action:      su3Action,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "signer",
				Usage: "Your SU3 signing ID (your email address)",
			},
			cli.StringFlag{
				Name:  "netdb",
				Usage: "Path to NetDB directory containing routerInfos",
			},
			cli.StringFlag{
				Name:  "keyfile",
				Value: "reseed_private.pem",
				Usage: "Path to your su3 signing private key",
			},
		},
	}
}

func su3Action(c *cli.Context) {
	netdbDir := c.String("netdb")
	if netdbDir == "" {
		fmt.Println("--netdb is required")
		return
	}

	signerId := c.String("signer")
	if signerId == "" {
		fmt.Println("--signer is required")
		return
	}

	// load our signing privKey
	privKey, err := loadPrivateKey(c.String("keyfile"))
	if nil != err {
		log.Fatalln(err)
	}

	netdb := reseed.NewLocalNetDb(netdbDir)
	reseeder := reseed.NewReseeder(netdb)
	reseeder.SignerId = []byte(signerId)
	reseeder.SigningKey = privKey

	// make a fake peer
	seeds, err := reseeder.Seeds(reseed.Peer("127.0.0.1"))
	if nil != err {
		log.Fatalln(err)
	}

	// create an SU3 from the seed
	su3File, err := reseeder.CreateSu3(seeds)

	//write the file to disk
	data, err := su3File.MarshalBinary()
	if nil != err {
		log.Fatalln(err)
	}
	ioutil.WriteFile("i2pseeds.su3", data, 0777)
}
