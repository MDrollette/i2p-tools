package main

import (
	"os"

	"github.com/MDrollette/go-i2p/cmd"
	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "go-i2p"
	app.Version = "0.1.0"
	app.Usage = "I2P commands"
	app.Flags = []cli.Flag{}
	app.Commands = []cli.Command{
		cmd.NewReseedCommand(),
		cmd.NewSu3VerifyCommand(),
		cmd.NewKeygenCommand(),
		cmd.NewSu3Command(),
		cmd.NewSu3VerifyPublicCommand(),
	}

	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
