package cmd

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"github.com/MDrollette/go-i2p/reseed"
	"github.com/MDrollette/go-i2p/su3"
	"github.com/codegangsta/cli"
)

func NewSu3VerifyPublicCommand() cli.Command {
	return cli.Command{
		Name:        "check_all",
		Usage:       "Verify all publicly listed reseed servers",
		Description: "Verify all publicly listed reseed servers",
		Action:      su3VerifyPublicAction,
		Flags:       []cli.Flag{},
	}
}

func su3VerifyPublicAction(c *cli.Context) {
	public_servers := []string{
		"https://reseed.i2p-projekt.de/",
		"https://cowpuncher.drollette.com/netdb/",
		"https://i2p.mooo.com/netDb/",
		"https://193.150.121.66/netDb/",
		"https://netdb.i2p2.no/",
		"https://reseed.info/",
		"https://us.reseed.i2p2.no:444/",
		"https://uk.reseed.i2p2.no:444/",
		"https://i2p-netdb.innovatio.no/",
		"https://ssl.webpack.de/ivae2he9.sg4.e-plaza.de/",
		"https://link.mx24.eu/",
		"https://ieb9oopo.mooo.com/",
	}

	responses := make(chan *http.Response)

	// Kick off goroutines to download the URLs
	go download(responses, public_servers)

	// Process them serially
	validate(responses)
}

func download(responses chan *http.Response, urls []string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Transport: tr}

	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			req, err := http.NewRequest("GET", fmt.Sprintf("%si2pseeds.su3", url), nil)
			if err != nil {
				log.Fatalln(err)
			}
			req.Header.Set("User-Agent", "Wget/1.11.4")
			resp, err := client.Do(req)
			if err != nil {
				log.Fatalln(err)
			}

			responses <- resp
		}(url)
	}

	// wait for all the responses to be handled
	wg.Wait()
	close(responses)
}

func validate(responses chan *http.Response) {
	ks := reseed.KeyStore{Path: "./certificates"}

	for resp := range responses {
		fmt.Printf("Validating: %s\n", resp.Request.URL)

		if resp.StatusCode != 200 {
			fmt.Printf("Invalid: Response code: %d\n", resp.StatusCode)
			fmt.Println("")
			continue
		}

		su3File := su3.Su3File{}
		data, err := ioutil.ReadAll(resp.Body)
		if nil != err {
			fmt.Println("Invalid: Unable to parse SU3 file:", err)
		}
		if err := su3File.UnmarshalBinary(data); err != nil {
			fmt.Println("Invalid: Unable to parse SU3 file:", err)
		}

		cert, err := ks.ReseederCertificate(su3File.SignerId)
		if nil != err {
			fmt.Println("Invalid: Unable to find public key.", err)
			fmt.Println("")
			continue
		}

		if err := su3File.VerifySignature(cert); nil != err {
			fmt.Println("Invalid: Unable to verify signature", err)
		} else {
			fmt.Printf("Valid: For signer '%s'\n", su3File.SignerId)
		}
		fmt.Println("")
	}
}
