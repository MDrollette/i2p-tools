package cmd

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/MDrollette/go-i2p/su3"
	"github.com/codegangsta/cli"
)

func NewSu3VerifyPublicCommand() cli.Command {
	return cli.Command{
		Name:        "vp",
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

	pipe := make(chan *http.Response)

	// Kick off goroutines to download the URLs
	go download(pipe, public_servers)

	// Process them serially
	validate(pipe)
}

func download(out chan *http.Response, urls []string) {
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

			out <- resp
		}(url)
	}

	wg.Wait()
	close(out)
}

func validate(in chan *http.Response) {
	for resp := range in {
		fmt.Printf("Validating: %s\n", resp.Request.URL)

		if resp.StatusCode != 200 {
			fmt.Printf("Invalid: Response code: %d\n", resp.StatusCode)
			fmt.Println("")
			continue
		}

		su3File, err := su3.Parse(resp.Body)
		if err != nil {
			fmt.Println("Invalid: Unable to parse SU3 file:", err)
		}
		resp.Body.Close()

		if err := su3File.VerifySignature(); nil != err {
			fmt.Println("Invalid: Unable to verify signature", err)
		} else {
			fmt.Printf("Valid: For signer '%s'\n", su3File.SignerId)
		}
		fmt.Println("")
	}
}
