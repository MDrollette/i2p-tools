package cmd

import (
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
				Name:  "netdb",
				Usage: "Path to NetDB directory containing routerInfos",
			},
			cli.StringFlag{
				Name:  "signer",
				Usage: "Your email address or su3 signing ID",
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
	// load our signing privKey
	privKey, err := loadPrivateKey(c.String("keyfile"))
	if nil != err {
		log.Fatalln(err)
	}

	netdb := reseed.NewLocalNetDb(c.String("netdb"))
	reseeder := reseed.NewReseeder(netdb)
	reseeder.SignerId = []byte(c.String("signer"))
	reseeder.SigningKey = privKey

	// make a fake peer
	peer := reseed.Peer("127.0.0.1")
	seeds, err := reseeder.Seeds(peer)
	if nil != err {
		log.Fatalln(err)
		return
	}

	// create an SU3 from the seed
	su3File, err := reseeder.CreateSu3(seeds)

	//write the file to disk
	ioutil.WriteFile("i2pseeds.su3", su3File.Bytes(), 0777)
}
