package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/takobas/vartadns/internal/dnsmsg"
)

// Identify maps a personal token (from the DoH path or the DoT SNI label)
// to the identity (IP) used for groups and logs. ok=false: unknown token.
type Identify func(token string) (identity netip.Addr, ok bool)

// ServeDoT answers DNS-over-TLS (RFC 7858) on a TLS listener. A client whose
// SNI is "<token>.<host>" with a known token is identified as that device
// (and may connect from anywhere); others must pass the client ACL.
func (r *Resolver) ServeDoT(ctx context.Context, ln net.Listener, host func() string, id Identify) {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case r.tcpSem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-r.tcpSem }()
			r.handleDoT(ctx, c, host, id)
		}()
	}
}

func (r *Resolver) handleDoT(ctx context.Context, c net.Conn, host func() string, id Identify) {
	defer c.Close()
	tc, ok := c.(*tls.Conn)
	if !ok {
		return
	}
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		return
	}
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	client := ap.Addr().Unmap()
	trusted := false
	sni := strings.ToLower(tc.ConnectionState().ServerName)
	if h := host(); h != "" && strings.HasSuffix(sni, "."+h) {
		if ident, ok := id(strings.TrimSuffix(sni, "."+h)); ok {
			client, trusted = ident, true
		}
	}
	if !trusted && len(r.opts.AllowedClients) > 0 && !inPrefixes(client, r.opts.AllowedClients) {
		return
	}
	var l [2]byte
	for {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second)) // RFC 7766 idle connections
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(l[:])
		if n < 12 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		resp := r.resolve(qctx, msg, client, "dot", trusted)
		cancel()
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// DoHHandler serves DNS-over-HTTPS (RFC 8484) at /dns-query and
// /dns-query/<token> (personal address of a device).
func (r *Resolver) DoHHandler(id Identify) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path
		if path != "/dns-query" && !strings.HasPrefix(path, "/dns-query/") {
			http.NotFound(w, req)
			return
		}
		ap, err := netip.ParseAddrPort(req.RemoteAddr)
		if err != nil {
			http.Error(w, "bad remote address", http.StatusBadRequest)
			return
		}
		client := ap.Addr().Unmap()
		trusted := false
		if tok := strings.Trim(strings.TrimPrefix(path, "/dns-query"), "/"); tok != "" {
			ident, ok := id(tok)
			if !ok {
				http.NotFound(w, req) // do not reveal which tokens exist
				return
			}
			client, trusted = ident, true
		}
		if !trusted && len(r.opts.AllowedClients) > 0 && !inPrefixes(client, r.opts.AllowedClients) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var msg []byte
		switch req.Method {
		case http.MethodGet:
			msg, err = base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
			if err != nil {
				http.Error(w, "bad dns parameter", http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if ct := req.Header.Get("Content-Type"); ct != "application/dns-message" {
				http.Error(w, "content-type must be application/dns-message", http.StatusUnsupportedMediaType)
				return
			}
			msg, err = io.ReadAll(http.MaxBytesReader(w, req.Body, 65535))
			if err != nil {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if len(msg) < 12 {
			http.Error(w, "short message", http.StatusBadRequest)
			return
		}
		// RFC 8484: the ID should be 0; keep the client's and restore it.
		resp := r.resolve(req.Context(), msg, client, "doh", trusted)
		if resp == nil {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "application/dns-message")
		if info, err := dnsmsg.Inspect(resp); err == nil && info.HasTTL {
			h.Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(info.MinTTL), 10))
		} else {
			h.Set("Cache-Control", "no-store")
		}
		_, _ = w.Write(resp)
	})
}
