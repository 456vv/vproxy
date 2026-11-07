package vproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const maxH2ConnsPerHost = 10 // 修复 #7：每 host 最多缓存 10 个 h2 连接
type h2clientConn struct {
	*http2.ClientConn
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
}

func (T *proxyHTTP) http2Client(poolKey string, req *http.Request) (*http.Response, bool) {
	T.mu.RLock()
	var h2cc *h2clientConn
	for _, cc := range T.h2Conns[poolKey] {
		if cc.CanTakeNewRequest() {
			h2cc = cc
			break
		}
	}
	T.mu.RUnlock()

	if h2cc != nil {
		resp, err := h2cc.RoundTrip(req)
		if err == nil {
			return resp, true
		}
		// RoundTrip 失败时 resp 可能非 nil，其 Body 需关闭避免 H2 stream 泄漏。
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		// 清理失效连接
		T.removeH2Conn(poolKey, h2cc)
	}
	return nil, false
}

// removeH2Conn 从池中移除指定 h2 连接并关闭
func (T *proxyHTTP) removeH2Conn(poolKey string, h2cc *h2clientConn) {
	T.mu.Lock()
	defer T.mu.Unlock()
	h2cc.Close()
	ccs := T.h2Conns[poolKey]
	for i, cc := range ccs {
		if cc == h2cc {
			T.h2Conns[poolKey] = append(ccs[:i], ccs[i+1:]...)
			break
		}
	}
	if len(T.h2Conns[poolKey]) == 0 {
		delete(T.h2Conns, poolKey)
	}
}

// h2PoolKey 生成 H2 连接池 key，必须包含影响 TLS 握手的参数。
func h2PoolKey(ctx context.Context, targetAddr string) string {
	skipVerify, _ := ctx.Value(ctxKeySkipVerify).(bool)
	browserVer, _ := ctx.Value(ctxKeyBrowserVer).(string)
	if !skipVerify && browserVer == "" {
		return targetAddr
	}
	return fmt.Sprintf("%t|%s|%s", skipVerify, browserVer, targetAddr)
}

// resetRequestBody 在 H2 复用尝试失败后，若 Body 可重放则重建 Body。
// 因为 htt2Client 内部复用的 h2 连接 RoundTrip 失败时，req.Body 可能已被读走；
// 若不重置，后续回退到 dialUTLS 新拨号会发送空 Body，导致目标端收到空请求体。
func resetRequestBody(req *http.Request) error {
	if req == nil || req.Body == nil || req.Body == http.NoBody || req.GetBody == nil {
		return nil
	}
	newBody, err := req.GetBody()
	if err != nil {
		return err
	}
	// 旧 Body 可能已被部分读取，关闭避免泄漏；重复 Close 通常无害。
	_ = req.Body.Close()
	req.Body = newBody
	return nil
}

func (T *proxyHTTP) roundTrip(req *http.Request) (*http.Response, error) {
	// 始终用 req.Context() 派生，保证 skipVerify/browserVer 与后续 dial 一致。
	ctx := req.Context()
	ctx = context.WithValue(ctx, ctxKeyRequest, req)
	targetAddr := host2addr(req.URL.Host, req.URL.Scheme)
	// H2 连接池 key 包含 skipVerify/browserVer，避免不安全连接被复用。
	poolKey := h2PoolKey(ctx, targetAddr)

	if req.URL.Scheme == "https" {
		// 尝试复用现有 H2 连接
		// 若 Body 不可重放（GetBody==nil 且 Body 非空），复用 H2 连接
		// 时若 RoundTrip 失败，Body 已被读走，后续回退拨号会发送空 Body。
		// 仅在 Body 为空或可重放时才尝试复用。
		canReuse := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
		if canReuse {
			if resp, ok := T.http2Client(poolKey, req); ok {
				return resp, nil
			}
			// H2 复用失败后重置可重放的 Body，避免后续回退拨号发送空 Body。
			if err := resetRequestBody(req); err != nil {
				return nil, err
			}
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
			// 请求成功，将连接加入池（按 poolKey 分桶）
			T.mu.Lock()
			var oldToClose *h2clientConn
			if ccs := T.h2Conns[poolKey]; len(ccs) >= maxH2ConnsPerHost {
				oldToClose = ccs[0]
				T.h2Conns[poolKey] = ccs[1:]
			}
			T.h2Conns[poolKey] = append(T.h2Conns[poolKey], &h2clientConn{ClientConn: h2Conn})
			T.mu.Unlock()
			if oldToClose != nil {
				oldToClose.Close()
			}
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
	// 防御 URL 为 nil 的请求（正常代理请求不会出现，避免 panic）。
	if req.URL == nil {
		T.proxy.resErr(rw, "request URL is nil")
		return
	}
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

	// 必须 WithContext，否则 roundTrip 内 h2PoolKey/dialUTLS 读不到 skipVerify/browserVer。
	cReq := req.WithContext(ctx)
	cReq.RequestURI = ""

	if cReq.URL.Host != "" {
		cReq.Host = cReq.URL.Host
	} else if cReq.Host != "" {
		cReq.URL.Host = cReq.Host
	}
	if cReq.URL.Scheme == "" {
		switch _, port := targetHostPort(cReq); port {
		case "80":
			cReq.URL.Scheme = "http"
		case "443":
			cReq.URL.Scheme = "https"
		default:
			if cReq.TLS == nil {
				cReq.URL.Scheme = "http"
			} else {
				cReq.URL.Scheme = "https"
			}
		}
	}

	cleanProxyHeaders(cReq)
	// 清理请求端逐跳头，避免转发给上游。

	removeHopHeaders(cReq.Header)
	resp, err := T.roundTrip(cReq)
	if err != nil {
		T.proxy.resErr(rw, err.Error())
		return
	}
	defer resp.Body.Close()

	T.proxy.logf(Response, "响应：\r\n%v", resp)

	// 清理响应端逐跳头；resp.Header 由 Transport 每次新建，可直接修改。
	removeHopHeaders(resp.Header)

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

	for k, vv := range resp.Trailer {
		for _, v := range vv {
			rw.Header().Add(http.TrailerPrefix+k, v)
		}
	}
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
		AllowHTTP: false,
	}
	return t2.NewClientConn(uConn)
}

func (T *proxyHTTP) newUTLSConn(ctx context.Context, conn net.Conn, targetAddr string) (*utls.UConn, error) {
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
	if ver, ok := ctx.Value(ctxKeyBrowserVer).(string); ok && ver != "" {
		// 注意：utls 对未知 Version 可能 panic（取决于 utls 内部实现）。
		// 空字符串走 HelloChrome_Auto；非空由用户保证是 utls 已知版本，否则风险自负。
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
	return T.newUTLSConn(ctx, conn, addr)
}

// hopHeaders 是 RFC 7230 §6.1 定义的逐跳头，代理不应转发。
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopHeaders 删除逐跳头，以及 Connection 头中列出的其他头。符合 RFC 7230 §6.1。
func removeHopHeaders(h http.Header) {
	// 先读取 Connection 值，再删除（删除后无法读取）。
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}
