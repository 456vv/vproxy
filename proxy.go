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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/456vv/vweb/v3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"golang.org/x/net/http2"
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
	lMu           sync.RWMutex // 保护 l 的并发读写（Serve 写 / Close 读）
	phttp         *proxyHTTP
	pconn         *proxyConnect
	initOnce      sync.Once // 同一个 Once 内同时初始化 phttp 和 pconn
	sshClient     *ssh.Client
	sshMu         sync.Mutex

	// known_hosts 文件路径列表，为空时使用 ~/.ssh/known_hosts（若存在）。
	KnownHostsFiles []string
	// 显式跳过 host key 校验。默认为 false（严格校验）。
	// 仅在调试或明确知晓风险时设为 true。
	InsecureIgnoreHostKey bool
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
		// TLS 启用且 NextProtos 含 "h2" 时必须注册 h2 处理器。
		// 否则 http.Server.Serve 对协商为 "h2" 的连接因 TLSNextProto["h2"]==nil
		// 会静默关闭，h2 入站全部失败（客户端无 fallback）。
		// 仅当用户 NextProtos 明确包含 "h2" 时才配置，避免对纯 http/1.1 用户强制启用 h2。
		if hasProto(srv.TLSConfig.NextProtos, "h2") && srv.TLSNextProto == nil {
			if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
				p.logf(Error, "http2.ConfigureServer: %v", err)
			}
		}
		if p.CertManager != nil {
			srv.Handler = vweb.AutoCert(p.CertManager, srv.TLSConfig, srv.Handler)
		}
	}
	return srv
}

// hasProto 判断 protos 是否包含 want。
func hasProto(protos []string, want string) bool {
	return slices.Contains(protos, want)
}

func (p *Proxy) resErr(rw http.ResponseWriter, err string) {
	p.logf(Error, "%s", err)
	http.Error(rw, err, http.StatusBadGateway)
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.logf(OriginAddr, "接入客户端IP: %s", req.RemoteAddr)

	// 1) 认证（若启用）
	if p.Auth != nil {
		username, password, ok := p.authenticate(req, rw)
		if !ok {
			return
		}
		if !p.Auth(username, password) {
			p.logf(Authenticate, "认证用户：%s，密码：%s", username, password)
			rw.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%s"`, username))
			http.Error(rw, "User or password is not valid!", http.StatusProxyAuthRequired)
			return
		} else {
			p.logf(Authenticate, "认证用户：%s", username)
		}
	}

	// 2) LinkPosterior 先把真实目标写入 req.Host / req.URL.Host，
	if p.LinkPosterior && !p.handleLinkPosterior(req, rw) {
		return
	}

	// 3) 自环检测：任何情况都执行（有认证时也需防代理连自己导致递归）。
	if err := p.checkSelfLoop(req); err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}

	// 4) 无认证时：禁止访问本机任意地址、任意端口。
	if p.Auth == nil {
		if err := p.checkLocalAccess(req); err != nil {
			http.Error(rw, err.Error(), http.StatusForbidden)
			return
		}
	}

	p.logf(Host, "%s Host: %s", req.Method, req.Host)
	p.logf(URI, "URI: %s", req.RequestURI)
	p.logf(Request, "请求：\r\n%v", req)

	if req.Method == http.MethodConnect {
		p.getProxyConnect().ServeHTTP(rw, req)
		return
	}
	p.getProxyHTTP().ServeHTTP(rw, req)
}

// checkSelfLoop 检测「请求目标就是代理自身监听地址+端口」的自环。
// 必须任何情况都执行：有认证时允许访问本机其它端口，但连回代理自身会造成
// CONNECT/转发的递归拨号，最终耗尽连接。
func (p *Proxy) checkSelfLoop(req *http.Request) error {
	localAddr, ok := req.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if !ok || localAddr == nil {
		return nil
	}
	tHost, tPort := targetHostPort(req)
	if tHost == "" || tPort == "" {
		return nil
	}
	// 先比端口短路：端口不同绝不可能是「连回自己」
	if tPort != strconv.Itoa(localAddr.Port) {
		return nil
	}
	if isSelfHost(tHost, localAddr.IP) {
		return fmt.Errorf("connection loopback error: target %q points to proxy itself", req.Host)
	}
	return nil
}

// checkLocalAccess 仅在无认证时调用：禁止访问本机任意地址（任意端口）。
// 覆盖范围：localhost 系列、环回、通配地址、代理监听 IP、本机所有网卡 IP。
func (p *Proxy) checkLocalAccess(req *http.Request) error {
	localAddr, ok := req.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if !ok || localAddr == nil {
		return nil
	}
	tHost, _ := targetHostPort(req)
	if tHost == "" {
		return nil
	}
	if isSelfHost(tHost, localAddr.IP) {
		return fmt.Errorf("access to local address %q is forbidden without authentication", req.Host)
	}
	return nil
}

// targetHostPort 提取目标 host / port；无端口时按 scheme 补默认端口。
// 说明：优先 req.Host（代理请求与 CONNECT 均填写），LinkPosterior 处理后 req.Host 已是真实目标。
func targetHostPort(req *http.Request) (host, port string) {
	target := req.Host
	if target == "" && req.URL != nil {
		target = req.URL.Host
	}
	if target == "" {
		return "", ""
	}
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		h = target
		scheme := ""
		if req.URL != nil {
			scheme = req.URL.Scheme
		}
		switch scheme {
		case "http":
			p = "80"
		default:
			p = "443"
		}
	}
	// SplitHostPort 对 IPv6 已去方括号，这里兜底
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return h, p
}

// 缓存本机网卡地址列表，避免无认证路径下每请求触发一次 syscall。
// TTL 设为 30s，兼顾实时性与性能；网卡 IP 变更最多 30s 后生效，安全边界可接受。
var localAddrsCache struct {
	mu    sync.Mutex
	addrs []net.IP
	exp   time.Time
}

func localAddrs() []net.IP {
	localAddrsCache.mu.Lock()
	defer localAddrsCache.mu.Unlock()
	if time.Now().Before(localAddrsCache.exp) {
		return localAddrsCache.addrs
	}
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	ips := make([]net.IP, 0, len(ifaces))
	for _, a := range ifaces {
		switch v := a.(type) {
		case *net.IPNet:
			ips = append(ips, v.IP)
		case *net.IPAddr:
			ips = append(ips, v.IP)
		}
	}
	localAddrsCache.addrs = ips
	localAddrsCache.exp = time.Now().Add(30 * time.Second)
	return ips
}

// isSelfHost 判断 host 是否指向本机。
// 只处理特殊名与字面 IP，不对任意域名做 DNS 解析（避免每请求解析开销与不确定性）；
// 因此 example.com 解析到本机这种极端场景不会被识别，属于可接受的安全折中。
func isSelfHost(host string, listenIP net.IP) bool {
	if host == "" {
		return false
	}
	switch strings.ToLower(host) {
	case "localhost", "ip6-localhost", "ip6-loopback":
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// 环回地址（127.0.0.0/8、::1）与通配地址（0.0.0.0、::）
	// 说明：连接 0.0.0.0/:: 在多数系统上等价于连本机。
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	if listenIP != nil && listenIP.Equal(ip) {
		return true
	}

	for _, ip2 := range localAddrs() {
		if ip2.Equal(ip) {
			return true
		}
	}
	return false
}

// 统一初始化，保证 phttp 和 pconn 均被创建
func (p *Proxy) getProxyHTTP() *proxyHTTP {
	p.initOnce.Do(func() {
		p.phttp = newProxyHTTP(p)
		p.pconn = newProxyConnect(p)
	})
	return p.phttp
}

func (p *Proxy) getProxyConnect() *proxyConnect {
	p.initOnce.Do(func() {
		p.phttp = newProxyHTTP(p)
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
		// Path 为空（如 CONNECT 请求）时避免切片越界 panic
		if len(req.URL.Path) > 0 {
			auth, upath, _ = strings.Cut(req.URL.Path[1:], "/")
		}

		if auth == "" || strings.HasSuffix(auth, ":") || !strings.Contains(auth, ":") {
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
			lower := strings.ToLower(rawurl)
			fixed := false
			for _, s := range []string{"https:", "http:", "wss:", "ws:"} {
				if strings.HasPrefix(lower, s) {
					rawurl = rawurl[:len(s)] + "//" + rawurl[len(s):]
					fixed = true
					break
				}
			}
			if !fixed {
				rawurl = "//" + rawurl
			}
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
	// 写 l 前持锁，避免与并发的 Close() 读取 l 形成 data race。
	p.lMu.Lock()
	p.l = l
	p.lMu.Unlock()
	p.Addr = l.Addr().String()

	muxListener := &protocolMuxListener{
		Listener:  l,
		tlsConfig: srv.TLSConfig,
	}
	return srv.Serve(muxListener)
}

func (p *Proxy) Close() error {
	// 读 l 时持读锁，避免与并发的 Serve() 写 l 形成 data race。
	p.lMu.RLock()
	l := p.l
	p.lMu.RUnlock()
	if l != nil {
		l.Close()
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

	if localAddr, ok := req.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok {
		upHost, _, _ := net.SplitHostPort(paddr)
		if upHost == "" {
			upHost = paddr
		}
		if isSelfHost(upHost, localAddr.IP) {
			return nil, fmt.Errorf("upstream proxy %q points to proxy itself", purl.Host)
		}
	}
	switch purl.Scheme {
	case "socks5", "socks5h":
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

		// socks5 本地解析目标域名，socks5h 保留域名交代理远程解析。
		// golang.org/x/net/proxy.SOCKS5 收到域名时直接传给代理（即 socks5h 语义），
		// 因此 "socks5" 需先本地解析为 IP。
		// 注意：解析失败时退回原 targetAddr（让代理尝试解析），避免硬失败。
		dialTarget := targetAddr
		if purl.Scheme == "socks5" {
			if tcpAddr, rerr := net.ResolveTCPAddr("tcp", targetAddr); rerr == nil {
				dialTarget = tcpAddr.String()
			}
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, dialTarget)
		}
		return dialer.Dial(network, dialTarget)
	case "socks4", "socks":
		// golang.org/x/net/proxy 仅提供 SOCKS5 实现，因此 SOCKS4 不被支持。
		// 如需真正 SOCKS4 支持，请引入专用实现（如 github.com/armon/go-socks5 不适用，需 socks4 库）。
		return nil, fmt.Errorf("proxy scheme %q is not supported, use socks5/socks5h", purl.Scheme)
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
		hostname, _, err := net.SplitHostPort(paddr)
		if err != nil {
			hostname = paddr
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
			ServerName:         hostname, // 修复：改为上游代理 hostname
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: purl.Query().Get("skipVerify") == "true",
		}
		conn = tls.Client(conn, tlsconfig)
		return connProxy(ctx, conn, targetAddr, basic)
	case "ssh":
		if purl.User == nil {
			return nil, errors.New("ssh proxy requires username in URL (ssh://user:pass@host:22)")
		}
		username := purl.User.Username()
		sshPwd, _ := purl.User.Password()

		// 快路径：锁内检查已有可用连接
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
		p.sshMu.Unlock()

		config := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				ssh.Password(sshPwd),
			},
			// 使用 knownhosts 严格校验 host key，替代原来的“无条件接受”。
			HostKeyCallback: p.buildHostKeyCallback(),
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
			return nil, err
		}

		// 慢路径完成后双重检查，避免并发重复建连
		p.sshMu.Lock()
		if p.sshClient != nil {
			existing := p.sshClient
			p.sshMu.Unlock()
			client.Close()
			return existing.DialContext(ctx, network, targetAddr)
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

func copyData(dst io.Writer, src io.ReadCloser, bufSize int) (int64, error) {
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
	if cap(*buf) < bufSize {
		*buf = make([]byte, bufSize)
	}
	defer bufferPool.Put(buf)

	var total int64
	for {
		n, err := src.Read((*buf)[:bufSize])
		if n > 0 {
			total += int64(n)
			if _, werr := dst.Write((*buf)[:n]); werr != nil {
				return total, werr
			}
			if fl != nil {
				fl.Flush()
			} else if fl2 != nil {
				_ = fl2.Flush()
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
	const prefix = "basic "
	// RFC 7235 要求认证 scheme 大小写不敏感。
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	before, after, ok := strings.Cut(cs, ":")
	if !ok {
		return
	}
	return before, after, true
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
	// ssh 握手阶段也可能无限阻塞，设置截止时间。
	if config.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(config.Timeout))
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{}) // 握手完成清除截止时间
	return ssh.NewClient(c, chans, reqs), nil
}

// buildHostKeyCallback 根据 Proxy 配置构建 SSH 主机密钥校验回调。
// 返回值保证非 nil，调用方无需再判断。
func (p *Proxy) buildHostKeyCallback() ssh.HostKeyCallback {
	if p.InsecureIgnoreHostKey {
		// 显式跳过校验：仅在用户明确设置时生效。
		p.logf(Error, "ssh: host key verification disabled (InsecureIgnoreHostKey=true); MITM risk")
		return ssh.InsecureIgnoreHostKey()
	}

	files := p.KnownHostsFiles
	if len(files) == 0 {
		// 未显式指定时，尝试默认位置 ~/.ssh/known_hosts。
		if home, err := os.UserHomeDir(); err == nil {
			defaultPath := filepath.Join(home, ".ssh", "known_hosts")
			if _, statErr := os.Stat(defaultPath); statErr == nil {
				files = []string{defaultPath}
			}
		}
	}

	if len(files) == 0 {
		// 没有可用的 known_hosts 文件：拒绝连接比“静默接受任意 key”更安全。
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return fmt.Errorf("ssh: no known_hosts file configured for host %q; "+
				"set Proxy.KnownHostsFiles or Proxy.InsecureIgnoreHostKey explicitly", hostname)
		}
	}

	cb, err := knownhosts.New(files...)
	if err != nil {
		// 文件存在但解析失败（权限/格式问题）同样返回拒绝型回调。
		p.logf(Error, "ssh: load known_hosts %v: %v", files, err)
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return fmt.Errorf("ssh: known_hosts unavailable: %w", err)
		}
	}

	// 包装原始回调，区分“未知主机”与“密钥变更”，便于日志和排障。
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) == 0 {
				// 主机未知：提示用户将服务器公钥加入 known_hosts。
				p.logf(Error, "ssh: unknown host %q (%s); add its host key to known_hosts: %s",
					hostname, remote, ssh.FingerprintSHA256(key))
				return fmt.Errorf("ssh: host %q is not in known_hosts", hostname)
			}
			// 密钥不匹配：高优先级安全事件（可能是 MITM）。
			p.logf(Error, "ssh: HOST KEY MISMATCH for %q (%s); possible MITM! presented=%s",
				hostname, remote, ssh.FingerprintSHA256(key))
			return fmt.Errorf("ssh: host key mismatch for %q (possible MITM)", hostname)
		}
		// 其他底层错误（I/O 等）原样返回。
		return err
	}
}
