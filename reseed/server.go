package reseed

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/PuerkitoBio/throttled"
	"github.com/PuerkitoBio/throttled/store"
	"github.com/gorilla/handlers"
	"github.com/justinas/alice"
)

const (
	I2P_USER_AGENT = "Wget/1.11.4"
)

type Server struct {
	*http.Server
	Reseeder Reseeder
}

func NewServer() *Server {
	config := &tls.Config{MinVersion: tls.VersionTLS10}
	h := &http.Server{TLSConfig: config}
	server := Server{h, nil}

	th := throttled.RateLimit(throttled.PerHour(4), &throttled.VaryBy{RemoteAddr: true}, store.NewMemStore(10000))

	middlewareChain := alice.New(proxiedMiddleware, loggingMiddleware, verifyMiddleware, th.Throttle)

	mux := http.NewServeMux()
	mux.Handle("/i2pseeds.su3", middlewareChain.Then(http.HandlerFunc(server.reseedHandler)))
	server.Handler = mux

	return &server
}

func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Index")
}

func (s *Server) reseedHandler(w http.ResponseWriter, r *http.Request) {
	peer := s.Reseeder.Peer(r)

	seeds, err := s.Reseeder.Seeds(peer)
	if nil != err {
		http.Error(w, "500 Unable to provide seeds", http.StatusInternalServerError)
		return
	}

	su3, err := s.Reseeder.CreateSu3(seeds)
	if nil != err {
		http.Error(w, "500 Unable to generate SU3", http.StatusInternalServerError)
		return
	}

	io.Copy(w, bytes.NewReader(su3.Bytes()))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return handlers.CombinedLoggingHandler(os.Stdout, next)
}

func verifyMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if I2P_USER_AGENT != r.UserAgent() {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func proxiedMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			r.RemoteAddr = prior[0]
		}

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
