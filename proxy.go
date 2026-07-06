package vproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/456vv/vweb/v3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"

	"golang.org/x/net/proxy"
)

const defaultDataBufioSize = 1 << 20 // 默认数据缓冲1MB

type LogLevel int

const (
	OriginAddr LogLevel = iota + 1
	Authenticate
	Host
	URI
	Request
	Response
	Error
)

var defaultDial = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

type Proxy struct {
	LinkPosterior bool
	DataBufioSize int
	Auth          func(username, password string) bool
	Addr          string
	Server        http.Server
	DialContext   func(ctx context.Context, network, address string) (net.Conn, error)
	ProxyURL      func(*http.Request) (*url.URL, error)
	ErrorLog      *log.Logger
	ErrorLogLevel LogLevel
	CertManager   *autocert.Manager // 自动申请证书 Let's Encrypt
	l             net.Listener
	phttp         *proxyHTTP
	pconn         *proxyConnect
	initOnce      sync.Once // For safe lazy init
	sshClient     *ssh.Client
	sshMu         sync.Mutex // Added for SSH safety
}

func (p *Proxy) initServer() *http.Server {
	srv := &p.Server
	if srv.Handler == nil {
		srv.Handler = http.HandlerFunc(p.ServeHTTP)
	}
	if srv.TLSConfig != nil {
		if srv.TLSConfig.NextProtos == nil {
			srv.TLSConfig.NextProtos = []string{"http/1.1", "h2"}
		}
		if p.CertManager != nil {
			srv.Handler = vweb.AutoCert(p.CertManager, srv.TLSConfig, srv.Handler)
		}
	}
	return srv
}

func (p *Proxy) resErr(rw http.ResponseWriter, err string) {
	p.logf(Error, "%s", err)
	http.Error(rw, err, http.StatusBadGateway)
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.logf(OriginAddr, "接入客户端IP: %s", req.RemoteAddr)

	// Authentication
	if p.Auth != nil {
		username, password, ok := p.authenticate(req, rw)
		if !ok {
			return
		}
		p.logf(Authenticate, "认证用户：%s，密码：%s", username, password)
		if !p.Auth(username, password) {
			rw.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%s"`, username))
			http.Error(rw, "User or password is not valid!", http.StatusProxyAuthRequired)
			return
		}
	} else if err := p.checkLoopback(req); err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}

	if p.LinkPosterior && !p.handleLinkPosterior(req, rw) {
		return
	}

	p.logf(Host, "%s Host: %s", req.Method, req.Host)
	p.logf(URI, "URI: %s", req.RequestURI)
	p.logf(Request, "请求：\r\n%v", req)

	// Route request
	if req.Method == http.MethodConnect {
		p.getProxyConnect().ServeHTTP(rw, req)
		return
	}

	p.getProxyHTTP().ServeHTTP(rw, req)
}

// Helper for safe lazy initialization
func (p *Proxy) getProxyHTTP() *proxyHTTP {
	p.initOnce.Do(func() {
		p.phttp = newProxyHTTP(p)
	})
	return p.phttp
}

func (p *Proxy) getProxyConnect() *proxyConnect {
	p.initOnce.Do(func() {
		p.pconn = newProxyConnect(p)
	})
	return p.pconn
}

func (p *Proxy) authenticate(req *http.Request, rw http.ResponseWriter) (username, password string, ok bool) {
	auth := req.Header.Get("Proxy-Authorization")
	if auth != "" {
		username, password, ok = parseBasicAuth(auth)
		if ok {
			return
		}
	}

	username, password, ok = req.BasicAuth()
	if ok {
		return
	}

	// Query param fallback
	query := req.URL.Query()
	auth = query.Get("@auth")
	if auth != "" {
		query.Del("@auth")
		req.URL.RawQuery = query.Encode()
	} else {
		var upath string
		var found bool
		auth, upath, found = strings.Cut(req.URL.Path[1:], "/")
		if !found || strings.HasSuffix(auth, ":") || !strings.Contains(auth, ":") {
			rw.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
			http.Error(rw, "Proxy server requires authentication", http.StatusProxyAuthRequired)
			return "", "", false
		}
		req.URL.Path = "/" + upath
	}

	auths := strings.SplitN(auth, ":", 2)
	if len(auths) != 2 {
		http.Error(rw, "Invalid auth format. Use %3A for ':' in credentials", http.StatusNotImplemented)
		return "", "", false
	}

	username, err1 := url.QueryUnescape(auths[0])
	password, err2 := url.QueryUnescape(auths[1])
	ok = err1 == nil && err2 == nil
	return
}

func (p *Proxy) handleLinkPosterior(req *http.Request, rw http.ResponseWriter) bool {
	var rawurl string
	if len(req.URL.Path) > 1 {
		rawurl = req.URL.Path[1:]
	} else {
		query := req.URL.Query()
		rawurl = query.Get("@url")
		if rawurl != "" {
			query.Del("@url")
			req.URL.RawQuery = query.Encode()
		}
	}

	if rawurl != "" {
		if rawurl == "favicon.ico" {
			http.Error(rw, "Connection path error!", http.StatusBadRequest)
			return false
		}
		if !strings.Contains(rawurl, "//") {
			rawurl = "//" + rawurl
		}
		lpurl, err := url.Parse(rawurl)
		if err != nil {
			p.logf(Host, "%s Host: %s", req.Method, req.Host)
			p.logf(URI, "连接路径错误: %s", req.RequestURI)
			http.Error(rw, "Connection path error!", http.StatusBadRequest)
			return false
		}

		req.Host = lpurl.Host
		req.URL.User = lpurl.User
		req.URL.Host = lpurl.Host
		req.URL.Path = lpurl.Path
		if lpurl.RawQuery != "" {
			if req.URL.RawQuery != "" {
				lpurl.RawQuery = lpurl.RawQuery + "&" + req.URL.RawQuery
			}
			req.URL.RawQuery = lpurl.RawQuery
		}

		if lpurl.Scheme != "" {
			req.URL.Scheme = lpurl.Scheme
		}
	}
	return true
}

func (p *Proxy) checkLoopback(req *http.Request) error {
	localAddr, ok := req.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if !ok {
		return nil
	}

	lIP := localAddr.IP.String()
	lPort := strconv.Itoa(localAddr.Port)

	rIP, _, _ := net.SplitHostPort(req.RemoteAddr)
	rHost, rPort, err := net.SplitHostPort(req.Host)
	if err != nil {
		rHost = req.Host

		switch req.URL.Scheme {
		case "http":
			rPort = "80"
		default:
			rPort = "443"
		}
	}

	if rHost == "localhost" || rHost == "127.0.0.1" || rHost == "::1" || rHost == lIP {
		if lPort == rPort {
			return fmt.Errorf("connection loopback error")
		}
	}

	// 同Ip，同端口。拒绝循环
	if lIP == rIP && lPort == rPort {
		return fmt.Errorf("connection loopback error")
	}
	return nil
}

func (p *Proxy) ListenAndServe() error {
	addr := p.Addr
	if addr == "" {
		addr = ":0"
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return p.Serve(l)
}

func (p *Proxy) Serve(l net.Listener) error {
	srv := p.initServer()
	p.l = l
	p.Addr = l.Addr().String()

	muxListener := &protocolMuxListener{
		Listener:  l,
		tlsConfig: srv.TLSConfig,
	}
	return srv.Serve(muxListener)
}

func (p *Proxy) Close() error {
	if p.l != nil {
		p.l.Close()
	}
	if p.phttp != nil {
		p.phttp.CloseIdleConnections()
	}
	p.sshMu.Lock()
	if p.sshClient != nil {
		p.sshClient.Close()
		p.sshClient = nil
	}
	p.sshMu.Unlock()
	return nil
}

func (p *Proxy) logf(level LogLevel, format string, v ...any) {
	if p.ErrorLog != nil && p.ErrorLogLevel >= level {
		p.ErrorLog.Output(2, fmt.Sprintf(format, v...))
	}
}

func (p *Proxy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if p.ProxyURL != nil {
		return p.proxyConnect(ctx, network, addr)
	} else if p.DialContext != nil {
		return p.DialContext(ctx, network, addr)
	}
	return defaultDial.DialContext(ctx, network, addr)
}

func (p *Proxy) proxyConnect(ctx context.Context, network, targetAddr string) (net.Conn, error) {
	req, ok := ctx.Value(ctxKeyRequest).(*http.Request)
	if !ok {
		return nil, errors.New("context missing http.Request")
	}

	purl, err := p.ProxyURL(req)
	if err != nil {
		return nil, err
	}
	var (
		basic string
		pwd   string
	)
	if purl.User != nil {
		pwd, _ = purl.User.Password()
		basic = basicAuth(purl.User.Username(), pwd)
	}
	paddr := host2addr(purl.Host, purl.Scheme)

	switch purl.Scheme {
	case "socks5", "socks5h", "socks4", "socks":
		var auth *proxy.Auth
		if purl.User != nil {
			auth = &proxy.Auth{
				User: purl.User.Username(),
			}
			auth.Password, _ = purl.User.Password()
		}
		var d proxy.Dialer
		if p.DialContext != nil {
			d = dialContext(p.DialContext)
		} else {
			d = dialContext(defaultDial.DialContext)
		}
		dialer, err := proxy.SOCKS5("tcp", paddr, auth, d)
		if err != nil {
			return nil, fmt.Errorf("socks5 dialer: %w", err)
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, targetAddr)
		}
		return dialer.Dial(network, targetAddr)
	case "http":
		var conn net.Conn
		if p.DialContext != nil {
			conn, err = p.DialContext(ctx, network, paddr)
		} else {
			conn, err = defaultDial.DialContext(ctx, network, paddr)
		}
		if err != nil {
			return nil, err
		}
		return connProxy(ctx, conn, targetAddr, basic)
	case "https":
		hostname, _, err := net.SplitHostPort(targetAddr)
		if err != nil {
			hostname = targetAddr
		}

		var conn net.Conn
		if p.DialContext != nil {
			conn, err = p.DialContext(ctx, network, paddr)
		} else {
			conn, err = defaultDial.DialContext(ctx, network, paddr)
		}
		if err != nil {
			return nil, err
		}
		tlsconfig := &tls.Config{
			ServerName:         hostname,                                 // 证书验证
			MinVersion:         tls.VersionTLS12,                         // 最低版本TLS1.2
			InsecureSkipVerify: purl.Query().Get("skipVerify") == "true", // 忽略证书验证
		}
		conn = tls.Client(conn, tlsconfig)
		return connProxy(ctx, conn, targetAddr, basic)
	case "ssh":
		p.sshMu.Lock()
		if p.sshClient != nil {
			_, _, err := p.sshClient.Conn.SendRequest("keepalive@proxy.dev", true, nil)
			if err == nil {
				client := p.sshClient
				p.sshMu.Unlock()
				return client.DialContext(ctx, network, targetAddr)
			}
			p.sshClient.Close()
			p.sshClient = nil
		}
		config := &ssh.ClientConfig{
			User: purl.User.Username(),
			Auth: []ssh.AuthMethod{
				ssh.Password(pwd),
			},
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				log.Println(hostname, remote, key)
				return nil
			},
			HostKeyAlgorithms: []string{
				ssh.KeyAlgoRSA,
				ssh.KeyAlgoECDSA256,
				ssh.KeyAlgoSKECDSA256,
				ssh.KeyAlgoECDSA384,
				ssh.KeyAlgoECDSA521,
				ssh.KeyAlgoED25519,
				ssh.KeyAlgoSKED25519,
			},
			Timeout: 10 * time.Second,
		}

		client, err := sshClient("tcp", paddr, config)
		if err != nil {
			p.sshMu.Unlock()
			return nil, err
		}
		p.sshClient = client
		p.sshMu.Unlock()
		return client.DialContext(ctx, network, targetAddr)

	}
	return nil, fmt.Errorf("this %s proxy type does not support", purl.Scheme)
}

type dialContext func(ctx context.Context, network, address string) (net.Conn, error)

func (d dialContext) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d(ctx, network, address)
}

func (d dialContext) Dial(network, address string) (net.Conn, error) {
	return d(context.Background(), network, address)
}

// Improved copy with buffer pooling and better error handling
var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, defaultDataBufioSize)
		return &b
	},
}

func copyData(dst io.Writer, src io.ReadCloser, bufSize int) (int, error) {
	defer src.Close()

	if bufSize <= 0 {
		bufSize = defaultDataBufioSize
	}

	var fl http.Flusher
	var fl2 interface{ Flush() error }

	if f, ok := dst.(http.Flusher); ok {
		fl = f
	} else if f, ok := dst.(interface{ Flush() error }); ok {
		fl2 = f
	}

	buf := bufferPool.Get().(*[]byte)
	// Ensure capacity is sufficient before use
	if cap(*buf) < bufSize {
		*buf = make([]byte, bufSize)
	}
	defer bufferPool.Put(buf)

	var total int
	for {
		n, err := src.Read((*buf)[:bufSize]) // Read into the available capacity
		if n > 0 {
			total += n
			if _, werr := dst.Write((*buf)[:n]); werr != nil {
				return total, werr
			}
			if fl != nil {
				fl.Flush()
			} else if fl2 != nil {
				fl2.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return total, err
		}
	}
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

func connProxy(ctx context.Context, conn net.Conn, address, basic string) (net.Conn, error) {
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}

	if basic != "" {
		connectReq.Header.Add("Proxy-Authorization", "Basic "+basic)
	}

	var (
		connectCtx, cancel = context.WithTimeout(ctx, 1*time.Minute)
		didReadResponse    = make(chan struct{})
		resp               *http.Response
		err                error
		br                 *bufio.Reader
	)
	defer cancel()

	go func() {
		defer close(didReadResponse)
		err = connectReq.Write(conn)
		if err != nil {
			return
		}
		br = bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, connectReq)
	}()
	select {
	case <-connectCtx.Done():
		conn.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
		// resp or err now set
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.Close()
		_, text, ok := strings.Cut(resp.Status, " ")
		if !ok {
			return nil, errors.New("unknown status code")
		}
		return nil, errors.New(text)
	}
	// 返回包裹的连接以防代理链预读数据丢失
	return &bufferConn{Conn: conn, br: br}, nil
}

type bufferConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

func (c *bufferConn) WriteTo(w io.Writer) (int64, error) {
	return c.br.WriteTo(w)
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func sshClient(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout(network, addr, config.Timeout)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return ssh.NewClient(c, chans, reqs), nil
}
