package main

import (
	"github.com/codegangsta/cli"
	"os"
	"time"
)

func main() {
	app := cli.NewApp()
	app.Name = "reseeder"
	app.Version = "1.0.0"
	app.Usage = "I2P reseed server"

	app.Commands = []cli.Command{
		{
			Name:      "serve",
			ShortName: "s",
			Usage:     "Start an http server for SU3 files",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "addr",
					Value: "",
					Usage: "Address to bind to",
				},
				cli.StringFlag{
					Name:  "port",
					Value: "8080",
					Usage: "Port to listen on",
				},
				cli.StringFlag{
					Name:  "cert",
					Value: "cert.pem",
					Usage: "Certificate for TLS",
				},
				cli.StringFlag{
					Name:  "key",
					Value: "key.pem",
					Usage: "Key for TLS certificate",
				},
				cli.StringFlag{
					Name:  "netdb",
					Value: "./netdb",
					Usage: "Path to NetDB directory containing routerInfo files",
				},
				cli.DurationFlag{
					Name:  "refresh",
					Value: 300 * time.Second,
					Usage: "Period to refresh routerInfo lists in time duration format (200ns, 1s, 5m)",
				},
				cli.BoolFlag{
					Name:  "proxy",
					Usage: "Trust the IP supplied in the X-Forwarded-For header",
				},
				cli.BoolFlag{
					Name:  "verbose",
					Usage: "Display all access logs",
				},
				cli.IntFlag{
					Name:  "rateLimit",
					Usage: "Maximum number of requests per minute per IP",
				},
			},
			Action: func(c *cli.Context) {
				server := NewReseeder()
				server.NetDBDir = c.String("netdb")
				server.RefreshInterval = c.Duration("refresh")
				server.Proxy = c.Bool("proxy")
				server.Verbose = c.Bool("verbose")
				server.RateLimit = c.Int("rateLimit")
				server.Start(c.String("addr"), c.String("port"), c.String("cert"), c.String("key"))
			},
		},
		{
			Name:      "generate",
			ShortName: "g",
			Usage:     "Generate a celf-signed certificate",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "host",
					Usage: "Comma-separated hostnames and IPs to generate a certificate for",
				},
				cli.StringFlag{
					Name:  "validFrom",
					Usage: "Creation date formatted as Jan 1 15:04:05 2011",
				},
				cli.DurationFlag{
					Name:  "validFor",
					Value: 2 * 365 * 24 * time.Hour,
					Usage: "Duration that certificate is valid for",
				},
				cli.BoolFlag{
					Name:  "ca",
					Usage: "Whether this cert should be its own Certificate Authority",
				},
				cli.IntFlag{
					Name:  "rsaBits",
					Value: 2048,
					Usage: "Size of RSA key to generate",
				},
			},
			Action: func(c *cli.Context) {
				GenerateCert(c.String("host"), c.String("validFrom"), c.Duration("validFor"), c.Bool("isCA"), c.Int("rsaBits"))
			},
		},
	}

	app.Run(os.Args)
}
