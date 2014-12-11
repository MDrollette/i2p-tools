package cmd

import (
	"fmt"
	"log"
	"net"
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
				Name:  "signer",
				Usage: "Your SU3 signing ID (your email address)",
			},
			cli.StringFlag{
				Name:  "netdb",
				Usage: "Path to NetDB directory containing routerInfos",
			},
			cli.StringFlag{
				Name:  "ip",
				Value: "0.0.0.0",
				Usage: "IP address to listen on",
			},
			cli.StringFlag{
				Name:  "port",
				Value: "9090",
				Usage: "Port to listen on",
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

	signerId := c.String("signer")
	if signerId == "" {
		fmt.Println("--signer is required")
		return
	}

	reloadIntvl, err := time.ParseDuration(c.String("interval"))
	if nil != err {
		log.Fatalf("'%s' is not a valid time interval.\n", reloadIntvl)
	}

	// use at most half of the cores
	cpus := runtime.NumCPU()
	if cpus >= 4 {
		runtime.GOMAXPROCS(cpus / 2)
	}

	// load our signing privKey
	// @todo: generate a new signing key if one doesn't exist
	privKey, err := loadPrivateKey(c.String("keyfile"))
	if nil != err {
		log.Fatalln(err)
	}

	// create a local file netdb provider
	netdb := reseed.NewLocalNetDb(netdbDir)

	// create a reseeder
	reseeder := reseed.NewReseeder(netdb)
	reseeder.SigningKey = privKey
	reseeder.SignerId = []byte(signerId)
	reseeder.NumRi = c.Int("numRI")
	reseeder.RebuildInterval = reloadIntvl
	reseeder.Start()

	// create a server
	server := reseed.NewServer()
	server.Reseeder = reseeder
	server.Addr = net.JoinHostPort(c.String("ip"), c.String("port"))

	// @todo check if tls cert exists, prompt to generate a new one if not

	log.Printf("Server listening on %s\n", server.Addr)
	server.ListenAndServeTLS(c.String("tlscert"), c.String("tlskey"))
}
