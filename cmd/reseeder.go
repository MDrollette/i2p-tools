package cmd

import (
	"log"

	// "github.com/MDrollette/go-i2p/reseed"
	"github.com/codegangsta/cli"
)

func NewReseederCommand() cli.Command {
	return cli.Command{
		Name:        "reseeder",
		Usage:       "Start a reseed server",
		Description: "Start a reseed server",
		Action:      reseederAction,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "addr",
				Value: "127.0.0.1:8080",
				Usage: "IP and port to listen on",
			},
		},
	}
}

func reseederAction(c *cli.Context) {
	log.Println("Starting server on", c.String("addr"))
}
