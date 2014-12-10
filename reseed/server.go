package reseed

import (
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/MDrollette/go-i2p/su3"
)

type routerInfo struct {
	Name string
	Data []byte
}

type Peer string
type Seed []routerInfo

type Reseeder interface {
	// seed a peer with routerinfos
	Seed(p Peer) (Seed, error)
	// get a peer from a given request
	Peer(r *http.Request) Peer
	// create an Su3 file from the given seeds
	CreateSu3(seeds Seed) (*su3.Su3File, error)
}

type ReseederImpl struct {
	netdb NetDbProvider
	peers map[string]Peer
	m     sync.Mutex
}

func NewReseeder(netdb NetDbProvider) *ReseederImpl {
	return &ReseederImpl{
		netdb: netdb,
		peers: make(map[string]Peer),
	}
}

func (rs *ReseederImpl) Seed(p Peer) (Seed, error) {
	all, err := rs.netdb.RouterInfos()
	if nil != err {
		return nil, err
	}

	return Seed(all), nil
}

func (rs *ReseederImpl) Peer(r *http.Request) Peer {
	rs.m.Lock()
	defer rs.m.Unlock()

	if p, ok := rs.peers[r.RemoteAddr]; !ok {
		rs.peers[r.RemoteAddr] = Peer(r.RemoteAddr)
	} else {
		return p
	}

	return rs.peers[r.RemoteAddr]
}

func (rs *ReseederImpl) CreateSu3(seeds Seed) (*su3.Su3File, error) {
	su3File := su3.NewSu3File()
	su3File.FileType = su3.FILE_TYPE_ZIP
	su3File.ContentType = su3.CONTENT_TYPE_RESEED

	zipped, err := zipSeeds(seeds)
	if nil != err {
		return nil, err
	}
	su3File.SetContent(zipped)

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
