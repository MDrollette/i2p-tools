package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/MDrollette/go-i2p/reseed"
	"github.com/MDrollette/go-i2p/su3"
	"github.com/codegangsta/cli"
)

func NewSu3Command() cli.Command {
	return cli.Command{
		Name:        "su3",
		Usage:       "Do SU3 things",
		Description: "Do SU3 things",
		Action:      su3Action,
		Flags:       []cli.Flag{},
	}
}

func su3Action(c *cli.Context) {
	netdb := reseed.NewLocalNetDb(c.Args().Get(0))
	reseeder := reseed.NewReseeder(netdb)

	// make a fake request to get a peer
	r, _ := http.NewRequest("GET", "/i2pseeds.su3", nil)

	peer := reseeder.Peer(r)
	seeds, err := reseeder.Seed(peer)
	if nil != err {
		log.Fatalln(err)
		return
	}

	// load our signing privKey
	privPem, err := ioutil.ReadFile("reseed_private.pem")
	if nil != err {
		log.Fatalln(err)
		return
	}
	privDer, _ := pem.Decode(privPem)
	privKey, err := x509.ParsePKCS1PrivateKey(privDer.Bytes)
	if nil != err {
		log.Fatalln(err)
		return
	}

	// create an SU3 from the seed
	su3File, err := reseeder.CreateSu3(seeds)
	su3File.SetSignerId("matt@drollette.com")
	// sign the su3 with our key
	su3File.Sign(privKey, su3.SIGTYPE_RSA_SHA512)

	//write the file to disk
	ioutil.WriteFile("i2pseeds.su3", su3File.Bytes(), 0777)
}
