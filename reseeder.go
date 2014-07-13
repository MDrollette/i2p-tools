package main

import (
	"flag"
	"fmt"
	"github.com/braintree/manners"
	"github.com/gorilla/handlers"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"
)

var netdbDir = flag.String("dir", "./netdb", "Location of your netdb directory")
var bindIp = flag.String("ip", "", "Interface to bind to")
var bindPort = flag.String("port", "3000", "Port to bind to")

func main() {
	flag.Parse()

	netdb := NewNetDb(*netdbDir)
	reseeder := &Reseeder{netdb, make([]*Peer, 100)}

	log.Printf("Starting server on %s:%s serving netdb from %s", *bindIp, *bindPort, *netdbDir)

	server := manners.NewServer()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		log.Println("waiting for connections to close and exiting...")
		server.Shutdown <- true
		go time.AfterFunc(time.Duration(5)*time.Second, func() {
			log.Println("Killing idle connections...")
			os.Exit(0)
		})
	}()

	err := server.ListenAndServe(*bindIp+":"+*bindPort, handlers.CombinedLoggingHandler(os.Stdout, reseeder))
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

type Reseeder struct {
	NetDb *NetDb
	Peers []*Peer
}

func (rs *Reseeder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	infos := make(chan *RouterInfo)

	peer := &Peer{req.RemoteAddr, time.Now(), time.Now()}

	go rs.GetForPeer(peer, infos)

	for info := range infos {
		fmt.Fprintf(w, "%s\n", info.Name)
	}
}

func (rs *Reseeder) GetForPeer(peer *Peer, infos chan *RouterInfo) {
	rs.NetDb.lock.RLock()
	defer rs.NetDb.lock.RUnlock()

	for _, info := range rs.NetDb.RouterInfos {
		infos <- info
	}
	close(infos)
}

func NewNetDb(dir string) *NetDb {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("netdb directory is not readable: %s", dir)
		} else {
			// other error
		}
	}
	netdb := &NetDb{Dir: dir, RouterInfos: make(map[string]*RouterInfo, 1000)}
	netdb.Refresh()

	return netdb
}

type NetDb struct {
	lock        sync.RWMutex
	RouterInfos map[string]*RouterInfo
	Dir         string
}

func (db *NetDb) Refresh() {
	files, err := ioutil.ReadDir(db.Dir)
	if nil != err {
		log.Fatalf("unable to read %s", db.Dir)
	}
	for _, file := range files {
		db.Set(file.Name(), NewRouterInfo(db.Dir+file.Name()))
	}
}

func (db *NetDb) Get(key string) (*RouterInfo, bool) {
	db.lock.RLock()
	defer db.lock.RUnlock()
	d, ok := db.RouterInfos[key]
	return d, ok
}

func (db *NetDb) Set(key string, d *RouterInfo) {
	db.lock.Lock()
	defer db.lock.Unlock()
	db.RouterInfos[key] = d
}

func (db *NetDb) UnSet(key string) {
	db.lock.Lock()
	defer db.lock.Unlock()
	delete(db.RouterInfos, key)
}

func NewRouterInfo(file string) *RouterInfo {
	return &RouterInfo{file}
}

type RouterInfo struct {
	Name string
}

type Peer struct {
	Ip      string
	Seen    time.Time
	Created time.Time
}

//// stuff for reverse proxy handling
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
