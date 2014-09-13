package main

// read in all files from netdb dir into a slice of routerinfos

// for every unique requesting IP
// look up that IP in the db
// - if it exists, check the creation time
// - if the creation time is within the threshold, serve up the routerinfos
// - if the creation time is outside the threshold, or if it does not exist generate a new slice of routerinfos from the current master set

// at some regular interval, update the master slice with fresh netdb routerinfos

// can serve up html/ul of routerinfos
// can serve up su3 signed file
// https://geti2p.net/en/docs/spec/updates

import (
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
	LIST_TEMPLATE = `<html><head><title>NetDB</title></head><body><ul>{{ range . }}<li><a href="{{ . }}">{{ . }}</a></li>{{ end }}</ul></body></html>`
)

func proxiedHandler(h http.Handler) http.Handler {
	return remoteAddrFixup{h}
}

type remoteAddrFixup struct {
	h http.Handler
}

func (h remoteAddrFixup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if prior, ok := r.Header["X-Forwarded-For"]; ok {
		r.RemoteAddr = prior[0]
	}
	h.h.ServeHTTP(w, r)
}

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

	if config.Proxy {
		muxWithMiddlewares = proxiedHandler(muxWithMiddlewares)
	}

	if config.Verbose {
		muxWithMiddlewares = handlers.CombinedLoggingHandler(os.Stdout, muxWithMiddlewares)
	}

	listenAddress := fmt.Sprintf("%s:%s", config.Addr, config.Port)

	if config.Cert != "" && config.Key != "" {
		log.Println("Starting http reseed server on " + listenAddress)
		err := http.ListenAndServeTLS(listenAddress, config.Cert, config.Key, muxWithMiddlewares)
		if nil != err {
			log.Fatalln(err)
		}
	} else {
		log.Println("Starting https reseed server on " + listenAddress)
		err := http.ListenAndServe(listenAddress, muxWithMiddlewares)
		if nil != err {
			log.Fatalln(err)
		}
	}
}

func NewLegacyReseeder(netdbDir string) *LegacyReseeder {
	return &LegacyReseeder{netdbDir: netdbDir, nextMap: make(chan []string)}
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
	nextMap      chan []string
	netdbDir     string
	listTemplate *template.Template
}

func (r *LegacyReseeder) Start(refreshInterval time.Duration) {
	go func() {
		var m []string
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
			r.Refresh()
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

func (r *LegacyReseeder) Refresh() {
	var m []string

	src, err := ioutil.ReadDir(r.netdbDir)
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
			m = append(m, file.Name())
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
	f, err := os.Open(rs.netdbDir + "/" + fileName)
	if nil != err {
		http.NotFound(w, r)
		log.Println("error sending file", err)
		return
	}
	io.Copy(w, f)
}
