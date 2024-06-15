package vproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultDataBufioSize = 1 << 20 // 默认数据缓冲1MB

type LogLevel int

const (
	OriginAddr   LogLevel = iota + 1 // 登录 vproxy 每个请求的目标。
	Authenticate                     // 认证
	Host                             // 访问的Host地址
	URI                              // 路径
	Request                          // 显示报头解析
	Response                         // 日志写入到网络的所有数据
	Error                            // 非致命错误
)

type Proxy struct {
	// 这个支持单条连接。不要使用在浏览器中。
	// 支持：
	// http://192.168.2.31/http://www.baidu.com/
	// http://192.168.2.31/?url=http://www.baidu.com/
	LinkPosterior bool                                                                 // 支持连接后面的，如：http://192.168.2.31/http://www.baidu.com/
	DataBufioSize int                                                                  // 缓冲区大小
	Auth          func(username, password string) bool                                 // 认证
	Addr          string                                                               // 代理IP地址
	Server        http.Server                                                          // 服务器
	DialContext   func(ctx context.Context, network, address string) (net.Conn, error) // 拨号
	ErrorLog      *log.Logger                                                          // 日志
	ErrorLogLevel LogLevel                                                             // 日志级别
	l             net.Listener                                                         // 连接对象
	Tr            http.RoundTripper                                                    // 代理
}

// initServer 初始化服务器
func (p *Proxy) initServer() *http.Server {
	srv := &p.Server
	if srv.Handler == nil {
		srv.Handler = http.HandlerFunc(p.ServeHTTP)
	}
	return srv
}

// ServeHTTP 处理服务
//
//	rw http.ResponseWriter  响应
//	req *http.Request       请求
func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if p.Tr == nil {
		p.Tr = http.DefaultTransport
	}

	p.logf(OriginAddr, "接入客户端IP: %s", req.RemoteAddr)

	// 认证用户密码
	if p.Auth != nil {
		var (
			username, password string
			ok                 bool
		)
		auth := req.Header.Get("Proxy-Authorization")
		if auth != "" {
			req.Header.Del("Proxy-Authorization")
			// 标头中读取
			username, password, ok = parseBasicAuth(auth)
		} else if username, password, ok = req.BasicAuth(); !ok {
			// 在query中读取
			query := req.URL.Query()
			auth = query.Get("@auth")
			if auth != "" {
				query.Del("@auth")
				req.URL.RawQuery = query.Encode()

				auths := strings.SplitN(auth, ":", 2)
				if len(auths) != 2 {
					http.Error(rw, "Connection parameters 'auth=user:pass' not set? user or pass exist ':' use %3A substitute！", http.StatusNotImplemented)
					return
				}
				var err error
				username, err = url.QueryUnescape(auths[0])
				if err == nil {
					password, err = url.QueryUnescape(auths[1])
					ok = err == nil
				}
			} else {
				http.Error(rw, "Proxy server link/requires authentication to log in!", http.StatusProxyAuthRequired)
				return
			}
		}
		p.logf(Authenticate, "认证用户：%s，密码：%s", username, password)
		if !ok || !p.Auth(username, password) {
			http.Error(rw, "User or password is not valid!", http.StatusProxyAuthRequired)
			return
		}
	}

	var rewriteHost bool
	if p.LinkPosterior {
		//http://www.baidu.com/			错的
		//http://www.baidu.com/a		对的
		//?url=http://www.baidu.com/*	对的

		var (
			rawurl string
			query  = req.URL.Query()
		)
		if len(req.URL.Path) > 1 {
			rawurl = req.URL.Path[1:]
		} else {
			rawurl = query.Get("@url")
			query.Del("@url")
			req.URL.RawQuery = query.Encode()
		}
		if strings.Index(rawurl, "//") == 0 || strings.Index(rawurl, "http://") == 0 || strings.Index(rawurl, "https://") == 0 {
			lpurl, err := url.Parse(rawurl)
			if err != nil {
				p.logf(Host, "%s Host: %s", req.Method, req.Host)
				p.logf(URI, "连接路径错误: %s", req.RequestURI)
				http.Error(rw, "Connection path error!", http.StatusBadRequest)
				return
			}
			rewriteHost = true
			req.Host = lpurl.Host
			req.URL.User = nil
			req.URL.Host = lpurl.Host
			req.URL.Path = lpurl.Path
			req.URL.RawQuery += "&" + lpurl.RawQuery
			if lpurl.Scheme != "" {
				req.URL.Scheme = lpurl.Scheme
			}
		}
	} else if req.URL.Host == "" {
		p.logf(URI, "连接路径错误: %s", req.RequestURI)
		http.Error(rw, "Connection path error!", http.StatusBadRequest)
		return
	}

	if localAddr, ok := req.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok && !rewriteHost {
		lhost := localAddr.IP.String()
		rhost, _, _ := net.SplitHostPort(req.RemoteAddr)

		lport := localAddr.Port
		_, rport, _ := net.SplitHostPort(req.Host)
		if rport == "" {
			switch req.URL.Scheme {
			case "http":
				rport = "80"
			case "https":
				rport = "443"
			}
		}
		// 同Ip，同端口。拒绝循环
		if lhost == rhost && strconv.Itoa(lport) == rport {
			http.Error(rw, "Connection loopback  error!", http.StatusBadRequest)
			return
		}
	}

	p.logf(Host, "%s Host: %s", req.Method, req.Host)
	p.logf(URI, "URI: %s", req.URL.String())
	p.logf(Request, "请求：\r\n%v", req)

	// 请求
	switch req.Method {
	case "CONNECT":
		cp := &proxyConnect{
			Proxy: p,
		}
		cp.ServeHTTP(rw, req)
	default:
		hp := &proxyHTTP{
			Proxy: p,
		}
		hp.ServeHTTP(rw, req)
	}
	// p.logf(OriginAddr, "断开客户端IP: %s", req.RemoteAddr)
}

// ListenAndServe 开启监听
//
//	返：
//	    error       错误
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

// Serve 开启监听
//
//	参：
//	    l net.Listener  监听对象
//	返：
//	    error           错误
func (p *Proxy) Serve(l net.Listener) error {
	srv := p.initServer()
	p.l = l
	p.Addr = l.Addr().String()
	srv.Addr = p.Addr
	if srv.TLSConfig != nil {
		l = tls.NewListener(l, srv.TLSConfig)
	}
	return srv.Serve(l)
}

// Close 关闭
//
//	返：
//	    error       错误
func (p *Proxy) Close() error {
	if tr, ok := p.Tr.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	if p.l != nil {
		return p.l.Close()
	}
	return nil
}

func (p *Proxy) logf(level LogLevel, format string, v ...interface{}) error {
	if p.ErrorLog != nil && p.ErrorLogLevel >= level {
		err := fmt.Errorf(format+"\n", v...)
		p.ErrorLog.Output(2, err.Error())
		return err
	}
	return nil
}

func copyDate(dst io.Writer, src io.ReadCloser, bufSize int) (n int64, err error) {
	defer src.Close()
	buf := make([]byte, bufSize)
	return io.CopyBuffer(dst, src, buf)
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

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
