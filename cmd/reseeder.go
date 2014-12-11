package cmd

import (
	"fmt"
	"log"
	"runtime"
	"time"

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
				Name:  "signer",
				Usage: "Your email address or su3 signing ID",
			},
			cli.StringFlag{
				Name:  "keyfile",
				Value: "reseed_private.pem",
				Usage: "Path to your su3 signing private key",
			},
			cli.IntFlag{
				Name:  "numRi",
				Value: 50,
				Usage: "Number of routerInfos to include in each SU3 file",
			},
			cli.StringFlag{
				Name:  "interval",
				Value: "12h",
				Usage: "Duration between SU3 cache rebuilds (ex. 12h, 15m)",
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

	cpus := runtime.NumCPU()
	if cpus >= 4 {
		runtime.GOMAXPROCS(cpus / 2)
	}

	// load our signing privKey
	privKey, err := loadPrivateKey(c.String("keyfile"))
	if nil != err {
		log.Fatalln(err)
	}

	// create a local file netdb provider
	netdb := reseed.NewLocalNetDb(netdbDir)

	// create a reseeder
	intr, err := time.ParseDuration(c.String("interval"))
	if nil != err {
		log.Fatalf("'%s' is not a valid time duration\n", intr)
	}

	reseeder := reseed.NewReseeder(netdb)
	reseeder.SigningKey = privKey
	reseeder.SignerId = []byte(c.String("signer"))
	reseeder.NumRi = c.Int("numRI")
	reseeder.RebuildInterval = intr
	reseeder.Start()

	// create a server
	server := reseed.NewServer()
	server.Reseeder = reseeder
	server.Addr = c.String("addr")

	// @todo generate self-signed keys if they don't exist

	log.Printf("Server listening on %s\n", server.Addr)
	server.ListenAndServeTLS(c.String("tlscert"), c.String("tlskey"))
}
