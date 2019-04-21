package main

import (
	"os"
	"runtime"

	"github.com/martin61/i2p-tools/cmd"
	"github.com/codegangsta/cli"
)

func main() {
	// TLS 1.3 is available only on an opt-in basis in Go 1.12. 
	// To enable it, set the GODEBUG environment variable (comma-separated key=value options) such that it includes "tls13=1". 
	// To enable it from within the process, set the environment variable before any use of TLS: 
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")

	// use at most half the cpu cores
	runtime.GOMAXPROCS(runtime.NumCPU() / 2)

	app := cli.NewApp()
	app.Name = "i2p-tools"
	app.Version = "0.1.7"
	app.Usage = "I2P tools and reseed server"
	app.Author = "martin61"
	app.Email = "noemail"
	app.Flags = []cli.Flag{}
	app.Commands = []cli.Command{
		cmd.NewReseedCommand(),
		cmd.NewSu3VerifyCommand(),
		cmd.NewKeygenCommand(),
		// cmd.NewSu3VerifyPublicCommand(),
	}

	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
