package main

import (
	"os"
	"runtime"

	"github.com/martin61/i2p-tools/cmd"
	"github.com/codegangsta/cli"
)

func main() {
	// use at most half the cpu cores
	runtime.GOMAXPROCS(runtime.NumCPU() / 2)

	app := cli.NewApp()
	app.Name = "i2p-tools"
	app.Version = "0.1.0"
	app.Usage = "I2P tools and reseed server"
	app.Author = "Matt Drollette"
	app.Email = "matt@drollette.com"
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
