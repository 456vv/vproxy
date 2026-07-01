package vproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type proxyHTTP struct {
	*http.Transport
	proxy   *Proxy
	mu      sync.RWMutex                 // Use RWMutex for better concurrency
	h2Conns map[string]*http2.ClientConn // H2 连接缓存 (per host)
}

type contextKey string

const (
	ctxKeyProxyConn  contextKey = "proxyConn"
	ctxKeySkipVerify contextKey = "skipVerify"
)

type connHolder struct {
	mu   sync.Mutex
	conn net.Conn
}

func (h *connHolder) Take() net.Conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.conn
	h.conn = nil
	return c
}

func newProxyHTTP(p *Proxy) *proxyHTTP {
	phttp := &proxyHTTP{
		Transport: &http.Transport{
			MaxIdleConns:        100, // Improved for performance
			MaxIdleConnsPerHost: 10,  // Better reuse
			IdleConnTimeout:     90 * time.Second,
			DialContext:         defaultDial.DialContext,
			// Enable HTTP/2 by default
			ForceAttemptHTTP2: true,
		},
		proxy:   p,
		h2Conns: make(map[string]*http2.ClientConn),
	}
	// http
	phttp.Transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if holder, ok := ctx.Value(ctxKeyProxyConn).(*connHolder); ok {
			if c := holder.Take(); c != nil {
				return c, nil
			}
		}
		if p.ProxyURL != nil {
			return nil, errors.New("unable to read prepared connection")
		}
		if p.DialContext != nil {
			return p.DialContext(ctx, network, addr)
		}
		return defaultDial.DialContext(ctx, network, addr)
	}

	// ssl
	phttp.Transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if holder, ok := ctx.Value(ctxKeyProxyConn).(*connHolder); ok {
			if c := holder.Take(); c != nil {
				return c, nil
			}
		}
		if p.ProxyURL != nil {
			return nil, errors.New("unable to read prepared connection")
		}
		return phttp.dialUTLS(ctx, network, addr)
	}

	return phttp
}

func (T *proxyHTTP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	query := req.URL.Query()
	skipVerify := query.Get("@skipVerify")
	if skipVerify == "true" {
		ctx = context.WithValue(ctx, ctxKeySkipVerify, true)
		query.Del("@skipVerify")
		req.URL.RawQuery = query.Encode()
	}

	cReq := req.Clone(ctx)
	cReq.RequestURI = ""
	if ae := cReq.Header["Accept-Encoding"]; len(ae) > 0 {
		cReq.Header["Accept-Encoding"] = []string{"gzip, deflate, br, zstd"}
	}

	resp, err := T.RoundTrip(cReq)
	if err != nil {
		T.proxy.resErr(rw, err.Error())
		return
	}

	T.proxy.logf(Response, "响应：\r\n%v", resp)

	wh := rw.Header()
	copyHeaders(wh, resp.Header)

	if len(resp.Trailer) > 0 {
		var trailerKeys []string
		for k := range resp.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}
	rw.WriteHeader(resp.StatusCode)

	if len(resp.Trailer) > 0 {
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

	// 优化 copyDate 调用，直接传递 Body
	copyDate(rw, resp.Body, T.proxy.DataBufioSize)
	resp.Body.Close()
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (T *proxyHTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "" {
		req.Host = req.URL.Host
	} else if req.Host != "" {
		req.URL.Host = req.Host
	}

	targetAddr := host2addr(req.URL.Host, req.URL.Scheme)
	ctx := req.Context()
	// 尝试复用已有的 H2 连接
	T.mu.RLock()
	cc, ok := T.h2Conns[targetAddr]
	T.mu.RUnlock()
	if ok && cc.CanTakeNewRequest() {
		if resp, err := cc.RoundTrip(req); err == nil {
			return resp, nil
		}
		// Cleanup stale
		T.mu.Lock()
		if T.h2Conns[targetAddr] == cc {
			delete(T.h2Conns, targetAddr)
			cc.Close()
		}
		T.mu.Unlock()
	}

	if T.proxy.ProxyURL != nil {
		conn, err := T.proxy.proxyConnect(ctx, req, targetAddr)
		if err != nil {
			return nil, err
		}

		if req.URL.Scheme == "https" {
			uConn, err := T.uConn(ctx, conn, targetAddr)
			if err != nil {
				conn.Close()
				return nil, err
			}
			if uConn.ConnectionState().NegotiatedProtocol == "h2" {
				h2Conn, err := T.http2ClientConn(uConn)
				if err != nil {
					uConn.Close()
					return nil, fmt.Errorf("h2 client conn: %w", err)

				}
				T.mu.Lock()
				T.h2Conns[targetAddr] = h2Conn
				T.mu.Unlock()
				return h2Conn.RoundTrip(req)
			}

			// h1
			conn = uConn
		}

		holder := &connHolder{conn: conn}
		ctx = context.WithValue(ctx, ctxKeyProxyConn, holder)
		req = req.WithContext(ctx)

		resp, err := T.Transport.RoundTrip(req)
		if unusedConn := holder.Take(); unusedConn != nil {
			unusedConn.Close()
		}
		return resp, err
	}

	return T.Transport.RoundTrip(req)
}

func (T *proxyHTTP) CloseIdleConnections() {
	T.mu.Lock()
	defer T.mu.Unlock()
	for k, cc := range T.h2Conns {
		cc.Close()
		delete(T.h2Conns, k)
	}
	T.Transport.CloseIdleConnections()
}

func (T *proxyHTTP) http2ClientConn(conn net.Conn) (*http2.ClientConn, error) {
	t2 := &http2.Transport{
		StrictMaxConcurrentStreams: true,
		AllowHTTP:                  false,
	}
	return t2.NewClientConn(conn)
}

func (T *proxyHTTP) uConn(ctx context.Context, conn net.Conn, targetAddr string) (*utls.UConn, error) {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
	}
	uconfig := &utls.Config{
		ServerName:         host,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: false, // Keep secure by default
	}
	if skip, ok := ctx.Value(ctxKeySkipVerify).(bool); ok {
		uconfig.InsecureSkipVerify = skip
	}
	tlsConn := utls.UClient(conn, uconfig, utls.HelloChrome_Auto)

	tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("utls handshake failed: %w", err)
	}

	// 握手完成，清除超时
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func (T *proxyHTTP) dialUTLS(ctx context.Context, network, addr string) (*utls.UConn, error) {
	var (
		conn net.Conn
		err  error
	)
	if T.proxy.DialContext != nil {
		conn, err = T.proxy.DialContext(ctx, network, addr)
	} else {
		conn, err = defaultDial.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	return T.uConn(ctx, conn, addr)
}
