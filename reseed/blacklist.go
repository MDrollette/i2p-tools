package reseed

import (
	"io/ioutil"
	"net"
	"strings"
	"sync"
)

type Blacklist struct {
	blacklist map[string]bool
	m         sync.RWMutex
}

func NewBlacklist() *Blacklist {
	return &Blacklist{blacklist: make(map[string]bool), m: sync.RWMutex{}}
}

func (s *Blacklist) LoadFile(file string) error {
	if file != "" {
		if content, err := ioutil.ReadFile(file); err == nil {
			for _, ip := range strings.Split(string(content), "\n") {
				s.BlockIp(ip)
			}
		} else {
			return err
		}
	}

	return nil
}

func (s *Blacklist) BlockIp(ip string) {
	s.m.Lock()
	defer s.m.Unlock()

	s.blacklist[ip] = true
}

func (s *Blacklist) isBlocked(ip string) bool {
	s.m.RLock()
	defer s.m.RUnlock()

	blocked, found := s.blacklist[ip]

	return found && blocked
}

type blacklistListener struct {
	*net.TCPListener
	blacklist *Blacklist
}

func (ln blacklistListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}

	ip, _, err := net.SplitHostPort(tc.RemoteAddr().String())
	if err != nil {
		tc.Close()
		return tc, err
	}

	if ln.blacklist.isBlocked(ip) {
		tc.Close()
		return tc, nil
	}

	return tc, err
}

func newBlacklistListener(ln net.Listener, bl *Blacklist) blacklistListener {
	return blacklistListener{ln.(*net.TCPListener), bl}
}
