package reseed

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/MDrollette/go-i2p/su3"
)

type routerInfo struct {
	Name string
	Data []byte
}

type Peer string

func (p Peer) Hash() int {
	b := sha256.Sum256([]byte(p))
	c := make([]byte, len(b))
	copy(c, b[:])
	return int(crc32.ChecksumIEEE(c))
}

type Seeds []routerInfo

type Reseeder interface {
	// seed a peer with routerinfos
	Seeds(p Peer) (Seeds, error)
	// get a peer from a given request
	Peer(r *http.Request) Peer
	// create an Su3 file from the given seeds
	CreateSu3(seeds Seeds) (*su3.Su3File, error)
	// get signed su3 bytes for a peer
	PeerSu3Bytes(peer Peer) ([]byte, error)
}

type ReseederImpl struct {
	netdb NetDbProvider
	su3s  chan [][]byte

	SigningKey      *rsa.PrivateKey
	SignerId        []byte
	NumRi           int
	RebuildInterval time.Duration
	numSu3          int
}

func NewReseeder(netdb NetDbProvider) *ReseederImpl {
	return &ReseederImpl{
		netdb:           netdb,
		su3s:            make(chan [][]byte),
		NumRi:           50,
		RebuildInterval: 12 * time.Hour,
		numSu3:          50,
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
	log.Println("Rebuilding su3s...")
	ris, err := rs.netdb.RouterInfos()
	if nil != err {
		return fmt.Errorf("Unable to get routerInfos: %s", err)
	}

	if rs.NumRi > len(ris) {
		return fmt.Errorf("Not enough routerInfos.")
	}

	newSu3s := make([][]byte, rs.numSu3)
	for i := 0; i < rs.numSu3; i++ {
		var seeds Seeds
		for _, z := range rand.Perm(rs.NumRi) {
			seeds = append(seeds, ris[z])
		}

		gs, err := rs.CreateSu3(seeds)
		if nil != err {
			return err
		}

		data, err := gs.MarshalBinary()
		if nil != err {
			return err
		}

		newSu3s[i] = data
	}

	rs.su3s <- newSu3s
	log.Println("Done rebuilding.")

	return nil
}

func (rs *ReseederImpl) PeerSu3Bytes(peer Peer) ([]byte, error) {
	hashMod := peer.Hash() % rs.numSu3

	m := <-rs.su3s
	defer func() { rs.su3s <- m }()

	return m[hashMod], nil
}

func (rs *ReseederImpl) Seeds(p Peer) (Seeds, error) {
	all, err := rs.netdb.RouterInfos()
	if nil != err {
		return nil, err
	}

	return Seeds(all), nil
}

func (rs *ReseederImpl) Peer(r *http.Request) Peer {
	return Peer(r.RemoteAddr)
}

func (rs *ReseederImpl) CreateSu3(seeds Seeds) (*su3.Su3File, error) {
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
	var src []os.FileInfo
	if src, err = ioutil.ReadDir(db.Path); nil != err {
		return
	}

	// randomize the file order
	files := make([]os.FileInfo, len(src))
	perm := rand.Perm(len(src))
	for i, v := range perm {
		files[v] = src[i]
	}

	r, _ := regexp.Compile("^routerInfo-[A-Za-z0-9-=~]+.dat$")

	for _, file := range files {
		if r.MatchString(file.Name()) {
			riBytes, err := ioutil.ReadFile(filepath.Join(db.Path, file.Name()))
			if nil != err {
				log.Println(err)
				continue
			}

			routerInfos = append(routerInfos, routerInfo{
				Name: file.Name(),
				Data: riBytes,
			})
		}
	}

	return
}
