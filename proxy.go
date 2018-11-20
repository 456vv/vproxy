package vproxy

import (
    "net/http"
    "net"
    "time"
    "io"
    "encoding/base64"
    "strings"
    "log"
    "fmt"
)

const defaultDataBufioSize    = 1<<20                                                       // 默认数据缓冲1MB

type LogLevel int
const (
    OriginAddr LogLevel    = iota+1 // 登录 vproxy 每个请求的目标。
    Authenticate                    // 认证
    Host                            // 访问的Host地址
    URI                             // 路径
    Request                         // 显示报头解析
    Response                        // 日志写入到网络的所有数据
    Error                           // 非致命错误
)


//Config 配置
type Config struct {
    DataBufioSize   int                                                                     // 缓冲区大小
    Auth            func(username, password string) bool                                    // 认证
    Timeout         time.Duration                                                           // 转发连接请求超时
    KeepAlive		time.Duration															// 保持连接心跳检测超时。如果为零，保持是未启用
    Deadline        time.Time                                                               // 转发连接请求超时
}

type Proxy struct {
    *Config                                                                                 // 配置
    Addr        string                                                                      // 代理IP地址
    Server      http.Server                                                                 // 服务器
    Transport   http.RoundTripper                                                           // 代理
    ErrorLog    *log.Logger                                                                 // 日志
    ErrorLogLevel LogLevel                                                                  // 日志级别
    l           net.Listener                                                                // 连接对象
}

//setDefault 设置默认
func (p *Proxy) setDefault(){
    if p.Transport == nil {
        p.Transport = http.DefaultTransport
    }
}

//initServer 初始化服务器
func (p *Proxy) initServer() *http.Server {
    srv := &p.Server
    if srv.Handler == nil {
        srv.Handler = http.HandlerFunc(p.ServeHTTP)
    }
    return srv
}

//ServeHTTP 处理服务
//  参：
//      rw http.ResponseWriter  响应
//      req *http.Request       请求
func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request){
    p.logf(OriginAddr, "", "接入客户端IP: %s", req.RemoteAddr)

    //认证用户密码
    if p.Auth != nil {
        auth := req.Header.Get("Proxy-Authorization")
        if auth == "" {
            p.logf(Authenticate, "", "请求标头 Proxy-Authorization 没有被设置？")
            http.Error(rw, "Proxy server requires authentication to log in!", http.StatusProxyAuthRequired)
            return
        }
        username, password, ok := parseBasicAuth(auth)
        p.logf(Authenticate, "", "认证用户：%s，密码：%s", username, password)
        if !ok || !p.Auth(username, password){
            p.logf(Authenticate, "", "用户或密码认证不通过？")
            http.Error(rw, "User or password is not valid!", http.StatusProxyAuthRequired)
            return
        }
    }

    p.logf(Host, "", "%s Host: %s", req.Method, req.Host)
    p.logf(URI, "", "URI: %s", req.RequestURI)
    p.logf(Request, "", "请求：\r\n%s", forType(req, ""))

    //请求
    switch req.Method {
        case "CONNECT":
            cp := &connectProxy{
                config      : p.Config,
                transport   : p.Transport,
                proxy       : p,
            }
            cp.ServeHTTP(rw, req)
        default:
            hp := &httpProxy{
                config      : p.Config,
                transport   : p.Transport,
                proxy       : p,
            }
            hp.ServeHTTP(rw, req)
    }
//    p.logf(OriginAddr, "", "断开客户端IP: %s", req.RemoteAddr)
}

//ListenAndServ 开启监听
//  返：
//      error       错误
func (p *Proxy) ListenAndServ() error {
    p.setDefault()
    srv := p.initServer()
    addr := p.Addr
    if addr == "" {
        addr = ":0"
    }
    l, err := net.Listen("tcp", addr)
    if err != nil {
        return err
    }
    p.l = l
    p.Addr = l.Addr().String()
    srv.Addr = p.Addr
    return srv.Serve(tcpKeepAliveListener{l.(*net.TCPListener)})
}

//Serve 开启监听
//  参：
//      l net.Listener  监听对象
//  返：
//      error           错误
func (p *Proxy) Serve(l net.Listener) error{
    p.setDefault()
    srv := p.initServer()
    p.l = l
    p.Addr = l.Addr().String()
    srv.Addr = p.Addr
    return p.Server.Serve(l)
}

//Close 关闭
//  返：
//      error       错误
func (p *Proxy) Close() error {
    if tr, ok := p.Transport.(*http.Transport); ok {
        tr.CloseIdleConnections()
    }
    if p.l != nil {
        return p.l.Close()
    }
    return nil
}

func (p *Proxy) logf(level LogLevel, funcName, format string, v ...interface{}){
    if p.ErrorLog != nil && p.ErrorLogLevel >= level {
        p.ErrorLog.Printf(fmt.Sprint(funcName, "->", format), v...)
    }
}

func copyDate(dst io.Writer, src io.ReadCloser, bufSize int) (n int64, err error){
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