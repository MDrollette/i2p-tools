package reseed

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/darknetj/i2p-tools/su3"
)

type routerInfo struct {
	Name    string
	ModTime time.Time
	Data    []byte
}

type Peer string

func (p Peer) Hash() int {
	b := sha256.Sum256([]byte(p))
	c := make([]byte, len(b))
	copy(c, b[:])
	return int(crc32.ChecksumIEEE(c))
}

type Reseeder interface {
	// get an su3 file (bytes) for a peer
	PeerSu3Bytes(peer Peer) ([]byte, error)
}

type ReseederImpl struct {
	netdb NetDbProvider
	su3s  chan [][]byte

	SigningKey      *rsa.PrivateKey
	SignerId        []byte
	NumRi           int
	RebuildInterval time.Duration
	NumSu3          int
}

func NewReseeder(netdb NetDbProvider) *ReseederImpl {
	return &ReseederImpl{
		netdb:           netdb,
		su3s:            make(chan [][]byte),
		NumRi:           75,
		RebuildInterval: 24 * time.Hour,
	}
}

func (rs *ReseederImpl) Start() chan bool {
	// atomic swapper
	go func() {
		var m [][]byte
		for {
			select {
			case m = <-rs.su3s:
			case rs.su3s <- m:
			}
		}
	}()

	// init the cache
	err := rs.rebuild()
	if nil != err {
		log.Println(err)
	}

	ticker := time.NewTicker(rs.RebuildInterval)
	quit := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				err := rs.rebuild()
				if nil != err {
					log.Println(err)
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	return quit
}

func (rs *ReseederImpl) rebuild() error {
	log.Println("Rebuilding su3 cache...")

	// get all RIs from netdb provider
	ris, err := rs.netdb.RouterInfos()
	if nil != err {
		return fmt.Errorf("Unable to get routerInfos: %s", err)
	}

	// use only 75% of routerInfos
	ris = ris[len(ris)/4:]

	// fail if we don't have enough RIs to make a single reseed file
	if rs.NumRi > len(ris) {
		return fmt.Errorf("Not enough routerInfos.")
	}

	// build a pipeline ris -> seeds -> su3
	seedsChan := rs.seedsProducer(ris)
	// fan-in multiple builders
	su3Chan := fanIn(rs.su3Builder(seedsChan), rs.su3Builder(seedsChan), rs.su3Builder(seedsChan))

	// read from su3 chan and append to su3s slice
	var newSu3s [][]byte
	for gs := range su3Chan {
		data, err := gs.MarshalBinary()
		if nil != err {
			return err
		}

		newSu3s = append(newSu3s, data)
	}

	// use this new set of su3s
	rs.su3s <- newSu3s

	log.Println("Done rebuilding.")

	return nil
}

func (rs *ReseederImpl) seedsProducer(ris []routerInfo) <-chan []routerInfo {
	lenRis := len(ris)

	// if NumSu3 is not specified, then we determine the "best" number based on the number of RIs
	var numSu3s int
	if rs.NumSu3 != 0 {
		numSu3s = rs.NumSu3
	} else {
		switch {
		case lenRis > 4000:
			numSu3s = 300
		case lenRis > 3000:
			numSu3s = 200
		case lenRis > 2000:
			numSu3s = 100
		case lenRis > 1000:
			numSu3s = 75
		default:
			numSu3s = 50
		}
	}

	log.Printf("Building %d su3 files each containing %d out of %d routerInfos.\n", numSu3s, rs.NumRi, lenRis)

	out := make(chan []routerInfo)

	go func() {
		for i := 0; i < numSu3s; i++ {
			var seeds []routerInfo
			unsorted := rand.Perm(lenRis)
			for z := 0; z < rs.NumRi; z++ {
				seeds = append(seeds, ris[unsorted[z]])
			}

			out <- seeds
		}
		close(out)
	}()

	return out
}

func (rs *ReseederImpl) su3Builder(in <-chan []routerInfo) <-chan *su3.Su3File {
	out := make(chan *su3.Su3File)
	go func() {
		for seeds := range in {
			gs, err := rs.createSu3(seeds)
			if nil != err {
				log.Println(err)
				continue
			}

			out <- gs
		}
		close(out)
	}()
	return out
}

func (rs *ReseederImpl) PeerSu3Bytes(peer Peer) ([]byte, error) {
	m := <-rs.su3s
	defer func() { rs.su3s <- m }()

	if 0 == len(m) {
		return nil, errors.New("404")
	}

	return m[peer.Hash()%len(m)], nil
}

func (rs *ReseederImpl) createSu3(seeds []routerInfo) (*su3.Su3File, error) {
	su3File := su3.NewSu3File()
	su3File.FileType = su3.FILE_TYPE_ZIP
	su3File.ContentType = su3.CONTENT_TYPE_RESEED

	zipped, err := zipSeeds(seeds)
	if nil != err {
		return nil, err
	}
	su3File.Content = zipped

	su3File.SignerId = rs.SignerId
	su3File.Sign(rs.SigningKey)

	return su3File, nil
}

type NetDbProvider interface {
	// Get all router infos
	RouterInfos() ([]routerInfo, error)
}

type LocalNetDbImpl struct {
	Path string
}

func NewLocalNetDb(path string) *LocalNetDbImpl {
	return &LocalNetDbImpl{
		Path: path,
	}
}

func (db *LocalNetDbImpl) RouterInfos() (routerInfos []routerInfo, err error) {
	r, _ := regexp.Compile("^routerInfo-[A-Za-z0-9-=~]+.dat$")

	files := make(map[string]os.FileInfo)
	walkpath := func(path string, f os.FileInfo, err error) error {
		if r.MatchString(f.Name()) {
			files[path] = f
		}
		return nil
	}

	filepath.Walk(db.Path, walkpath)

	for path, file := range files {
		riBytes, err := ioutil.ReadFile(path)
		if nil != err {
			log.Println(err)
			continue
		}

		// ignore outdate routerInfos
		age := time.Since(file.ModTime())
		if age.Hours() > 96 {
			continue
		}

		routerInfos = append(routerInfos, routerInfo{
			Name:    file.Name(),
			ModTime: file.ModTime(),
			Data:    riBytes,
		})
	}

	return
}

func fanIn(inputs ...<-chan *su3.Su3File) <-chan *su3.Su3File {
	out := make(chan *su3.Su3File, len(inputs))

	var wg sync.WaitGroup
	wg.Add(len(inputs))
	go func() {
		// close "out" when we're done
		wg.Wait()
		close(out)
	}()

	// fan-in all the inputs to a single output
	for _, input := range inputs {
		go func(in <-chan *su3.Su3File) {
			defer wg.Done()
			for n := range in {
				out <- n
			}
		}(input)
	}

	return out
}
