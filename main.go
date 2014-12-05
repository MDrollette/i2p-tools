package main

import (
	"os"

	"github.com/MDrollette/go-i2p/cmd"
	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "i2p"
	app.Version = "0.1.0"
	app.Usage = "I2P commands"
	app.Flags = []cli.Flag{}
	app.Before = func(c *cli.Context) error {
		cmd.Init()
		return nil
	}
	app.Commands = []cli.Command{
		cmd.NewReseederCommand(),
	}

	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
