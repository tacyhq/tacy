package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// dotServer is a DNS-over-TLS server answering every A query with 203.0.113.7 and every other type with no answer.
// It records the names asked.
type dotServer struct {
	l     net.Listener
	roots *x509.CertPool
	mu    sync.Mutex
	asked []string
}

func newDoTServer(t *testing.T) *dotServer {
	ts := httptest.NewUnstartedServer(nil) // only for its test certificate (valid for example.com and 127.0.0.1)
	ts.StartTLS()
	cert, roots := ts.TLS.Certificates[0], x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	ts.Close()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	s := &dotServer{l: l, roots: roots}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return s
}

func (s *dotServer) serve(c net.Conn) {
	defer c.Close()
	for {
		var n [2]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(n[:]))
		if _, err := io.ReadFull(c, q); err != nil || len(q) < 12 {
			return
		}
		// The question: labels from byte 12, then type and class.
		var labels []string
		i := 12
		for i < len(q) && q[i] != 0 {
			labels = append(labels, string(q[i+1:i+1+int(q[i])]))
			i += 1 + int(q[i])
		}
		qtype := binary.BigEndian.Uint16(q[i+1:])
		question := q[12 : i+5]
		s.mu.Lock()
		s.asked = append(s.asked, strings.Join(labels, "."))
		s.mu.Unlock()
		resp := append([]byte{}, q[:2]...)
		resp = append(resp, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0) // response, recursion; 1 question
		resp = append(resp, question...)
		if qtype == 1 {
			resp[7] = 1 // one answer
			resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
		if _, err := c.Write(append(out, resp...)); err != nil {
			return
		}
	}
}

func TestParseDoT(t *testing.T) {
	d, err := ParseDoT("dns.quad9.net@9.9.9.9:853,[2620:fe::fe]:853")
	if err != nil || d.Name != "dns.quad9.net" || len(d.Addrs) != 2 || d.Addrs[1] != "[2620:fe::fe]:853" {
		t.Fatalf("%+v %v", d, err)
	}
	for _, bad := range []string{"", "9.9.9.9:853", "dns.quad9.net@", "dns.quad9.net@dns.quad9.net:853", "dns.quad9.net@9.9.9.9", "a/b@9.9.9.9:853"} {
		if _, err := ParseDoT(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Every lookup goes over TLS to the pinned resolver, checked against its name; a resolver with another name, or
// none reachable, resolves nothing (no plain DNS fallback).
func TestDoTResolver(t *testing.T) {
	srv := newDoTServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := &DoT{Name: "example.com", Addrs: []string{srv.l.Addr().String()}, Roots: srv.roots}
	ips, err := d.Resolver().LookupHost(ctx, "pages.example.org")
	if err != nil || len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Fatalf("%v %v", ips, err)
	}
	srv.mu.Lock()
	asked := strings.Join(srv.asked, " ")
	srv.mu.Unlock()
	if !strings.Contains(asked, "pages.example.org") {
		t.Fatalf("the resolver was asked %q", asked)
	}

	// The certificate must carry the pinned name.
	wrong := &DoT{Name: "dns.other.example", Addrs: d.Addrs, Roots: srv.roots}
	if _, err := wrong.Resolver().LookupHost(ctx, "pages.example.org"); err == nil {
		t.Fatal("resolved through a resolver whose certificate has another name")
	}
	// Nothing reachable: nothing resolves (a closed port; the system's DNS is never asked).
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	down := &DoT{Name: "example.com", Addrs: []string{dead}, Roots: srv.roots}
	if _, err := down.Resolver().LookupHost(ctx, "localhost.example"); err == nil {
		t.Fatal("resolved with no resolver reachable")
	}
}
