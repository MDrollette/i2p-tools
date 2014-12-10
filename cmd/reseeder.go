package cmd

import (
	"fmt"
	"log"
	"net/http"

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
				Value: "127.0.0.1:8080",
				Usage: "IP and port to listen on",
			},
		},
	}
}

func reseedAction(c *cli.Context) {
	log.Println("Starting server on", c.String("addr"))

	netdb := reseed.NewLocalNetDb(c.Args().Get(0))
	reseeder := reseed.NewReseeder(netdb)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		peer := reseeder.Peer(r)
		seeds, err := reseeder.Seed(peer)
		if nil != err {
			fmt.Fprintf(w, "Problem: '%s'", err)
			return
		}

		for _, s := range seeds {
			fmt.Fprintf(w, "%s\n", s.Name)
		}
	})

	http.ListenAndServe("127.0.0.1:9090", nil)
}
