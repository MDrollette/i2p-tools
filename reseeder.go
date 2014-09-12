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

type Reseeder struct {
	NetDBDir        string
	nextMap         chan []string
	RefreshInterval time.Duration
}

func (rs *Reseeder) Start(addr, port, cert, key string) {
	log.Println("Starting reseed server on " + addr + ":" + port)

	r := mux.NewRouter()
	s := r.PathPrefix("/netdb").Subrouter()
	s.HandleFunc("/", rs.listHandler)
	//s.HandleFunc("/i2pseeds.su3", rs.su3Handler)
	s.HandleFunc(`/routerInfo-{hash:[A-Za-z0-9+/\-=~]+}.dat`, rs.routerInfoHandler)

	http.Handle("/", handlers.CombinedLoggingHandler(os.Stdout, proxiedHandler(r)))

	go rs.runMap()
	rs.Refresh()

	// sample function to update routerInfo map every minute
	go func() {
		for {
			time.Sleep(rs.RefreshInterval)
			log.Println("Updating routerInfos")
			rs.Refresh()
		}
	}()

	if _, err := os.Stat(cert); err == nil {
		if _, err := os.Stat(key); err == nil {
			err := http.ListenAndServeTLS(addr+":"+port, cert, key, nil)
			if nil != err {
				log.Fatalln(err)
			}
			return
		}
	}

	err := http.ListenAndServe(addr+":"+port, nil)
	if nil != err {
		log.Fatalln(err)
	}
}

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
	tmpl, err := template.New("foo").Parse(`<html><head><title>NetDB</title></head><body><ul>{{ range . }}<li><a href="{{ . }}">{{ . }}</a></li>{{ end }}</ul></body></html>`)
	if err != nil {
		panic(err)
	}

	err = tmpl.Execute(w, <-rs.nextMap)
	if err != nil {
		panic(err)
	}
}

func (rs *Reseeder) su3Handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "")
}

func (rs *Reseeder) routerInfoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileName := "routerInfo-" + vars["hash"] + ".dat"
	f, err := os.Open(rs.NetDBDir + "/" + fileName)
	if nil != err {
		log.Fatalln("error sending file", err)
		return
	}
	io.Copy(w, f)
}
