package vproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type h2clientConn struct {
	*http2.ClientConn
	used atomic.Bool
}
type proxyHTTP struct {
	*http.Transport
	proxy   *Proxy
	mu      sync.RWMutex               // Use RWMutex for better concurrency
	h2Conns map[string][]*h2clientConn // H2 连接缓存 (per host)\
}

type contextKey string

const (
	ctxKeyProxyConn  contextKey = "proxyConn"
	ctxKeySkipVerify contextKey = "skipVerify"
	ctxKeyBrowserVer contextKey = "browserVer"
	ctxKeyRequest    contextKey = "httpRequest"
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
	tr := &http.Transport{
		MaxIdleConns:        100, // Improved for performance
		MaxIdleConnsPerHost: 10,  // Better reuse
		IdleConnTimeout:     90 * time.Second,
	}
	phttp := &proxyHTTP{
		Transport: tr,
		proxy:     p,
		h2Conns:   make(map[string][]*h2clientConn),
	}

	// http
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if holder, ok := ctx.Value(ctxKeyProxyConn).(*connHolder); ok {
			if c := holder.Take(); c != nil {
				return c, nil
			}
		}
		return p.dial(ctx, network, addr)
	}

	// ssl
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if holder, ok := ctx.Value(ctxKeyProxyConn).(*connHolder); ok {
			if c := holder.Take(); c != nil {
				return c, nil
			}
		}
		return phttp.dialUTLS(ctx, network, addr)
	}

	return phttp
}

func cleanProxyHeaders(req *http.Request) {
	for k := range req.Header {
		if strings.HasPrefix(strings.ToLower(k), "proxy-") {
			delete(req.Header, k)
		}
	}

	req.Header.Set("referer", req.URL.String())                 // 设置 referer 为当前请求的 URL
	req.Header.Set("origin", req.URL.Scheme+"://"+req.URL.Host) // 设置 origin 为当前请求的协议和主机名
}

func (T *proxyHTTP) htt2Client(targetAddr string, req *http.Request) (*http.Response, bool) {
	T.mu.Lock()
	var h2cc *h2clientConn
	for _, cc := range T.h2Conns[targetAddr] {
		if cc.CanTakeNewRequest() && !cc.used.Swap(true) {
			h2cc = cc
			break
		}
	}
	T.mu.Unlock()
	if h2cc != nil {
		if resp, err := h2cc.RoundTrip(req); err == nil {
			h2cc.used.Store(false)
			return resp, true
		}

		// Cleanup stale
		T.mu.Lock()
		h2cc.Close()
		h2ccs := T.h2Conns[targetAddr]
		if len(h2ccs) == 1 && h2ccs[0] == h2cc {
			delete(T.h2Conns, targetAddr)
		} else {
			for i, cc := range h2ccs {
				if cc == h2cc {
					T.h2Conns[targetAddr] = append(h2ccs[:i], h2ccs[i+1:]...)
					break
				}
			}
		}
		T.mu.Unlock()
	}
	return nil, false
}

func (T *proxyHTTP) roundTrip(req *http.Request) (*http.Response, error) {
	ctx := context.WithValue(req.Context(), ctxKeyRequest, req)
	targetAddr := host2addr(req.URL.Host, req.URL.Scheme)

	if req.URL.Scheme == "https" {
		// 尝试复用现有 H2 连接
		if resp, ok := T.htt2Client(targetAddr, req); ok {
			return resp, nil
		}

		uConn, err := T.dialUTLS(ctx, "tcp", targetAddr)
		if err != nil {
			return nil, err
		}

		if uConn.ConnectionState().NegotiatedProtocol == "h2" {
			h2Conn, err := T.http2ClientConn(uConn)
			if err != nil {
				uConn.Close()
				return nil, fmt.Errorf("h2 client conn: %w", err)

			}
			resp, err := h2Conn.RoundTrip(req)
			if err != nil {
				h2Conn.Close()
				return nil, err
			}
			// 请求成功，将连接加入池
			T.mu.Lock()
			T.h2Conns[targetAddr] = append(T.h2Conns[targetAddr], &h2clientConn{ClientConn: h2Conn})
			T.mu.Unlock()
			return resp, nil
		}

		// HTTP/1.1 over TLS
		holder := &connHolder{conn: uConn}
		ctx = context.WithValue(ctx, ctxKeyProxyConn, holder)
		req = req.WithContext(ctx)
		resp, err := T.Transport.RoundTrip(req)
		if unusedConn := holder.Take(); unusedConn != nil {
			unusedConn.Close()
		}
		return resp, err
	}

	// HTTP (non-TLS)
	req = req.WithContext(ctx)
	return T.Transport.RoundTrip(req)
}

func (T *proxyHTTP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	query := req.URL.Query()

	if query.Get("@skipVerify") == "true" {
		ctx = context.WithValue(ctx, ctxKeySkipVerify, true)
		query.Del("@skipVerify")
		req.URL.RawQuery = query.Encode()
	}
	if browserVer := query.Get("@browserVer"); browserVer != "" {
		ctx = context.WithValue(ctx, ctxKeyBrowserVer, browserVer)
		query.Del("@browserVer")
		req.URL.RawQuery = query.Encode()
	}

	cReq := req.WithContext(ctx)
	cReq.RequestURI = ""
	if _, ok := cReq.Header["Accept-Encoding"]; !ok {
		cReq.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	}

	if cReq.URL.Host != "" {
		cReq.Host = cReq.URL.Host
	} else if cReq.Host != "" {
		cReq.URL.Host = cReq.Host
	}
	if cReq.URL.Scheme == "" {
		cReq.URL.Scheme = "https"
	}

	cleanProxyHeaders(cReq)
	resp, err := T.roundTrip(cReq)
	if err != nil {
		T.proxy.resErr(rw, err.Error())
		return
	}
	defer resp.Body.Close()

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

	if fl, ok := rw.(http.Flusher); ok && len(resp.Trailer) > 0 {
		fl.Flush()
	}

	// 优化 copyDate 调用，直接传递 Body
	copyData(rw, resp.Body, T.proxy.DataBufioSize)
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (T *proxyHTTP) CloseIdleConnections() {
	T.mu.Lock()
	defer T.mu.Unlock()
	for k, ccs := range T.h2Conns {
		for _, cc := range ccs {
			cc.Close()
		}
		delete(T.h2Conns, k)
	}
	T.Transport.CloseIdleConnections()
}

func (T *proxyHTTP) http2ClientConn(uConn net.Conn) (*http2.ClientConn, error) {
	t2 := &http2.Transport{
		StrictMaxConcurrentStreams: true,
		AllowHTTP:                  false,
	}
	return t2.NewClientConn(uConn)
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

	chromeVer := utls.HelloChrome_Auto
	if ver, ok := ctx.Value(ctxKeyBrowserVer).(string); ok {
		chromeVer = utls.ClientHelloID{Client: "Chrome", Version: ver, Seed: nil, Weights: nil}
	}

	tlsConn := utls.UClient(conn, uconfig, chromeVer)
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
	conn, err := T.proxy.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return T.uConn(ctx, conn, addr)
}
