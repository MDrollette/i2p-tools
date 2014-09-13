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
	"time"
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

type Reseeder struct {
	NetDBDir        string
	nextMap         chan []string
	RefreshInterval time.Duration
	Proxy           bool
	Verbose         bool
	RateLimit       int

	listTemplate *template.Template
}

func (rs *Reseeder) Start(addr, port, cert, key string) {
	var err error

	go rs.runMap()
	go rs.refresher()

	// parse the template for routerInfo lists
	rs.listTemplate, err = template.New("routerinfos").Parse(`<html><head><title>NetDB</title></head><body><ul>{{ range . }}<li><a href="{{ . }}">{{ . }}</a></li>{{ end }}</ul></body></html>`)
	if err != nil {
		log.Fatalln("error parsing routerInfo list template", err)
		return
	}

	r := mux.NewRouter()
	s := r.PathPrefix("/netdb").Subrouter()

	s.HandleFunc("/", rs.listHandler)
	s.HandleFunc("/i2pseeds.su3", rs.su3Handler)
	s.HandleFunc(`/routerInfo-{hash:[A-Za-z0-9+/\-=~]+}.dat`, rs.routerInfoHandler)

	// timeout
	muxWithMiddlewares := http.TimeoutHandler(r, time.Second*5, "Timeout!")

	th := throttled.RateLimit(throttled.PerMin(rs.RateLimit), &throttled.VaryBy{RemoteAddr: true}, store.NewMemStore(1000))
	muxWithMiddlewares = th.Throttle(muxWithMiddlewares)

	if rs.Proxy {
		muxWithMiddlewares = proxiedHandler(muxWithMiddlewares)
	}

	if rs.Verbose {
		muxWithMiddlewares = handlers.CombinedLoggingHandler(os.Stdout, muxWithMiddlewares)
	}

	// try to start tls server
	if _, err = os.Stat(cert); err == nil {
		if _, err = os.Stat(key); err == nil {
			log.Println("Starting TLS reseed server on " + addr + ":" + port)
			err := http.ListenAndServeTLS(addr+":"+port, cert, key, muxWithMiddlewares)
			if nil != err {
				log.Fatalln(err)
			}

			return
		}
	}

	// fall back to regular http server
	log.Println("Starting reseed server on " + addr + ":" + port)
	err = http.ListenAndServe(addr+":"+port, muxWithMiddlewares)
	if nil != err {
		log.Fatalln(err)
	}
}

func NewReseeder() *Reseeder {
	return &Reseeder{nextMap: make(chan []string)}
}

func (r *Reseeder) runMap() {
	var m []string
	for {
		select {
		case m = <-r.nextMap:
		case r.nextMap <- m:
		}
	}
}

func (r *Reseeder) refresher() {
	for {
		log.Println("Updating routerInfos")
		r.Refresh()
		time.Sleep(r.RefreshInterval)
	}
}

func (r *Reseeder) Refresh() {
	var m []string

	src, err := ioutil.ReadDir(r.NetDBDir)
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
		if !file.IsDir() && file.Name() != "." && file.Name() != ".." {
			m = append(m, file.Name())
			added++
		}
		if added >= 50 {
			break
		}
	}

	r.nextMap <- m
}

func (rs *Reseeder) listHandler(w http.ResponseWriter, r *http.Request) {
	err := rs.listTemplate.Execute(w, <-rs.nextMap)
	if err != nil {
		log.Fatalln("error rending list template", err)
	}
}

func (rs *Reseeder) su3Handler(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (rs *Reseeder) routerInfoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileName := "routerInfo-" + vars["hash"] + ".dat"
	f, err := os.Open(rs.NetDBDir + "/" + fileName)
	if nil != err {
		http.NotFound(w, r)
		log.Println("error sending file", err)
		return
	}
	io.Copy(w, f)
}
