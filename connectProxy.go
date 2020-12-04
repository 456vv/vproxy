package vproxy

import (
	"net/http"
    "net"
    "context"
    "time"
    "io"
)

var resultStatus200 = []byte("HTTP/1.1 200 Connection established\r\n\r\n")

type connectProxy struct{
    config      *Config
    transport   http.RoundTripper
    proxy       *Proxy
}

func minNonzeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

func (cp *connectProxy) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
    if cp.config.Timeout != 0 {
        earliest = now.Add(cp.config.Timeout)
    }
    if d, ok := ctx.Deadline(); ok {
    	earliest = minNonzeroTime(earliest, d)
    }
    return minNonzeroTime(earliest, cp.config.Deadline)
}

func (cp *connectProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request){
    var netConn net.Conn
    var err error
    var pproxy bool

    var ctx context.Context = req.Context()
    deadline := cp.deadline(ctx, time.Now())
    if !deadline.IsZero() {
        if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
            subCtx, cancel := context.WithDeadline(ctx, deadline)
            defer cancel()
            ctx = subCtx
        }
    }

    if tr, ok := cp.transport.(*http.Transport); ok{
        if tr.DialContext != nil {
            netConn, err = tr.DialContext(ctx, "tcp", req.Host)
        }else if tr.Dial != nil {
            netConn, err = tr.Dial("tcp", req.Host)
        }
        pproxy = tr.Proxy != nil
    }

    if netConn == nil {
        netConn, err = new(net.Dialer).DialContext(ctx, "tcp", req.Host)
    }

    if err != nil {
        cp.proxy.logf(Error, "", err.Error())
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
    }

    hj, ok := rw.(http.Hijacker)
	if !ok {
        netConn.Close()
        cp.proxy.logf(Error, "", "代理服务器不支持劫持客户端连接转TCP")
		http.Error(rw, "proxy server doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
        netConn.Close()
        cp.proxy.logf(Error, "", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

    if pproxy {
    	//表示还有上一级代理
        err = req.WriteProxy(netConn.(io.Writer))
        if err != nil {
            netConn.Close()
            cp.proxy.logf(Error, "", err.Error())
    		http.Error(rw, err.Error(), http.StatusBadGateway)
    		return
        }
    }else{
        conn.Write(resultStatus200)
    }

    var bufSize int = defaultDataBufioSize
    if cp.config != nil && cp.config.DataBufioSize != 0 {
        bufSize = cp.config.DataBufioSize
    }

    go copyDate(netConn, conn, bufSize)
    go copyDate(conn, netConn, bufSize)
}

