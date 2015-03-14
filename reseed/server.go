package reseed

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

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

func NewServer(prefix string, trustProxy bool) *Server {
	config := &tls.Config{
		MinVersion:               tls.VersionTLS10,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
	h := &http.Server{TLSConfig: config}
	server := Server{h, nil}

	th := throttled.RateLimit(throttled.PerDay(4), &throttled.VaryBy{RemoteAddr: true}, store.NewMemStore(100000))

	middlewareChain := alice.New()
	if trustProxy {
		middlewareChain = middlewareChain.Append(proxiedMiddleware)
	}

	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write(nil); nil != err {
			log.Println(err)
		}
	})

	mux := http.NewServeMux()
	mux.Handle("/", middlewareChain.Append(disableKeepAliveMiddleware, loggingMiddleware).Then(errorHandler))
	mux.Handle(prefix+"/i2pseeds.su3", middlewareChain.Append(disableKeepAliveMiddleware, loggingMiddleware, verifyMiddleware, th.Throttle).Then(http.HandlerFunc(server.reseedHandler)))
	server.Handler = mux

	return &server
}

func (s *Server) reseedHandler(w http.ResponseWriter, r *http.Request) {
	var peer Peer
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peer = Peer(ip)
	} else {
		peer = Peer(r.RemoteAddr)
	}

	su3Bytes, err := s.Reseeder.PeerSu3Bytes(peer)
	if nil != err {
		http.Error(w, "500 Unable to get SU3", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=i2pseeds.su3")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(su3Bytes)), 10))

	io.Copy(w, bytes.NewReader(su3Bytes))
}

func disableKeepAliveMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
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
