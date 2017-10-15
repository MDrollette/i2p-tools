package main

import (
	"os"
	"runtime"

	"github.com/MDrollette/i2p-tools/cmd"
	"github.com/codegangsta/cli"
)

func main() {
	// use at most half the cpu cores
	runtime.GOMAXPROCS(runtime.NumCPU() / 2)

	app := cli.NewApp()
	app.Name = "i2p-tools"
	app.Version = "0.1.7"
	app.Usage = "I2P tools and reseed server"
	app.Author = "MDrollette"
	app.Email = "matt@rows.io"
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
