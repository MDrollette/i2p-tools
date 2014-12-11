package cmd

import (
	"fmt"
	"log"

	"github.com/MDrollette/go-i2p/reseed"
	"github.com/codegangsta/cli"
)

func NewReseedCommand() cli.Command {
	return cli.Command{
		Name:        "reseed",
		Usage:       "Start a reseed server",
		Description: "Start a reseed server",
		Action:      reseedAction,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "addr",
				Value: "127.0.0.1:9090",
				Usage: "IP and port to listen on",
			},
			cli.StringFlag{
				Name:  "netdb",
				Usage: "Path to NetDB directory containing routerInfos",
			},
			cli.StringFlag{
				Name:  "tlscert",
				Value: "cert.pem",
				Usage: "Path to tls certificate",
			},
			cli.StringFlag{
				Name:  "tlskey",
				Value: "key.pem",
				Usage: "Path to tls key",
			},
			cli.StringFlag{
				Name:  "keyfile",
				Value: "reseed_private.pem",
				Usage: "Path to your su3 signing private key",
			},
		},
	}
}

func reseedAction(c *cli.Context) {
	netdbDir := c.String("netdb")
	if netdbDir == "" {
		fmt.Println("--netdb is required")
		return
	}

	// load our signing privKey
	privKey, err := loadPrivateKey(c.String("keyfile"))
	if nil != err {
		log.Fatalln(err)
	}

	// create a local file netdb provider
	netdb := reseed.NewLocalNetDb(netdbDir)

	// create a reseeder
	reseeder := reseed.NewReseeder(netdb)
	reseeder.SigningKey = privKey
	reseeder.SignerId = []byte("matt@drollette.com")

	// create a server
	server := reseed.NewServer()
	server.Reseeder = reseeder
	server.Addr = c.String("addr")

	// @todo generate self-signed keys if they don't exist

	log.Printf("Server listening on %s\n", server.Addr)
	server.ListenAndServeTLS(c.String("tlscert"), c.String("tlskey"))
}
