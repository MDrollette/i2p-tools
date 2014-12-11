package reseed

import (
	"bytes"
	"fmt"
	"github.com/PuerkitoBio/throttled"
	"github.com/PuerkitoBio/throttled/store"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"time"
)

const (
	LIST_TEMPLATE = `<html><head><title>NetDB</title></head><body><ul>{{ range $index, $_ := . }}<li><a href="{{ $index }}">{{ $index }}</a></li>{{ end }}</ul></body></html>`
)

type Config struct {
	NetDBDir        string
	RefreshInterval time.Duration
	Proxy           bool
	Verbose         bool
	RateLimit       int

	Addr string
	Port string
	Cert string
	Key  string
}

func Run(config *Config) {
	legacyReseeder := NewLegacyReseeder(config.NetDBDir)
	legacyReseeder.Start(config.RefreshInterval)

	su3Reseeder := NewSu3Reseeder(config.NetDBDir)
	su3Reseeder.Start()

	r := mux.NewRouter()
	s := r.PathPrefix("/netdb").Subrouter()

	s.HandleFunc("/", legacyReseeder.ListHandler)
	s.HandleFunc(`/routerInfo-{hash:[A-Za-z0-9-=~]+}.dat`, legacyReseeder.RouterInfoHandler)
	s.HandleFunc("/i2pseeds.su3", su3Reseeder.Su3Handler)

	th := throttled.RateLimit(throttled.PerMin(config.RateLimit), &throttled.VaryBy{RemoteAddr: true}, store.NewMemStore(1000))
	muxWithMiddlewares := th.Throttle(r)

	if config.Verbose {
		muxWithMiddlewares = handlers.CombinedLoggingHandler(os.Stdout, muxWithMiddlewares)
	}

	listenAddress := fmt.Sprintf("%s:%s", config.Addr, config.Port)

	if config.Cert != "" && config.Key != "" {
		log.Println("Starting https reseed server on " + listenAddress)
		err := http.ListenAndServeTLS(listenAddress, config.Cert, config.Key, muxWithMiddlewares)
		if nil != err {
			log.Fatalln(err)
		}
	} else {
		log.Println("Starting http reseed server on " + listenAddress)
		err := http.ListenAndServe(listenAddress, muxWithMiddlewares)
		if nil != err {
			log.Fatalln(err)
		}
	}
}

func NewLegacyReseeder(netdbDir string) *LegacyReseeder {
	return &LegacyReseeder{netdbDir: netdbDir, nextMap: make(chan map[string][]byte)}
}

func NewSu3Reseeder(netdbDir string) *Su3Reseeder {
	return &Su3Reseeder{netdbDir: netdbDir, nextMap: make(chan []string)}
}

type Su3Reseeder struct {
	nextMap  chan []string
	netdbDir string
}

func (r *Su3Reseeder) Start() {
}

func (rs *Su3Reseeder) Su3Handler(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

type LegacyReseeder struct {
	nextMap      chan map[string][]byte
	netdbDir     string
	listTemplate *template.Template
}

func (r *LegacyReseeder) Start(refreshInterval time.Duration) {
	go func() {
		var m map[string][]byte
		for {
			select {
			case m = <-r.nextMap:
			case r.nextMap <- m:
			}
		}
	}()

	go func() {
		for {
			log.Println("Updating routerInfos")
			r.Refresh(r.netdbDir)
			time.Sleep(refreshInterval)
		}
	}()

	// parse the template for routerInfo lists
	var err error
	r.listTemplate, err = template.New("ri").Parse(LIST_TEMPLATE)
	if err != nil {
		log.Fatalln("error parsing routerInfo list template", err)
		return
	}
}

func (r *LegacyReseeder) Refresh(netdbDir string) {
	m := make(map[string][]byte)

	src, err := ioutil.ReadDir(netdbDir)
	if nil != err {
		log.Fatalln("error reading netdb dir", err)
		return
	}

	// randomize the file order
	files := make([]os.FileInfo, len(src))
	perm := rand.Perm(len(src))
	for i, v := range perm {
		files[v] = src[i]
	}

	added := 0
	for _, file := range files {
		if match, _ := regexp.MatchString("^routerInfo-[A-Za-z0-9-=~]+.dat$", file.Name()); match {
			fi, err := os.Open(netdbDir + "/" + file.Name())
			if err != nil {
				log.Println("Error reading routerInfo file", err)
				continue
			}
			fileData, err := ioutil.ReadAll(fi)
			if nil != err {
				log.Println("Error reading routerInfo file", err)
				continue
			}
			fi.Close()

			m[file.Name()] = fileData
			added++
		}
		if added >= 50 {
			break
		}
	}

	r.nextMap <- m
}

func (lr *LegacyReseeder) ListHandler(w http.ResponseWriter, r *http.Request) {
	err := lr.listTemplate.Execute(w, <-lr.nextMap)
	if err != nil {
		log.Fatalln("error rending list template", err)
	}
}

func (rs *LegacyReseeder) RouterInfoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileName := "routerInfo-" + vars["hash"] + ".dat"

	m := <-rs.nextMap
	if b, ok := m[fileName]; ok {
		io.Copy(w, bytes.NewReader(b))
		return
	}

	http.NotFound(w, r)
	log.Println("error sending file", fileName)
}
