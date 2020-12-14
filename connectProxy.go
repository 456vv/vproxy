package vproxy

import (
	"net/http"
    "net"
    "context"
)

var resultStatus200 = []byte("HTTP/1.1 200 Connection established\r\n\r\n")

type proxyConnect struct{
    *Proxy
}


func host2addr(host, scheme string) string {
    rh, rp, _ := net.SplitHostPort(host)
    if rp == "" {
    	rp = "443"
    	if scheme == "http" {
    		rp = "80"
    	}
    }
    return net.JoinHostPort(rh, rp)
}

func (T *proxyConnect) ServeHTTP(rw http.ResponseWriter, req *http.Request){
    var (
    	remoteConn net.Conn
    	err error
       	remoteAddr = host2addr(req.URL.Host, req.URL.Scheme)
    	ctx = req.Context()
    )
	var dial func(ctx context.Context, network, address string) (net.Conn, error)
	if T.Proxy.DialContext != nil {
		dial = T.Proxy.DialContext
	}else{
		dial = new(net.Dialer).DialContext
	}
	remoteConn, err = dial(ctx, "tcp", remoteAddr)
    if err != nil {
        T.Proxy.logf(Error, err.Error())
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
    }
	
	
    hj, ok := rw.(http.Hijacker)
	if !ok {
		remoteConn.Close()
        T.Proxy.logf(Error, "代理服务器不支持劫持客户端连接转TCP")
		http.Error(rw, "Proxy server doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		remoteConn.Close()
        T.Proxy.logf(Error, err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	
	conn.Write(resultStatus200)
	
    var bufSize int = defaultDataBufioSize
    if T.Proxy.DataBufioSize != 0 {
        bufSize = T.Proxy.DataBufioSize
    }
	
    go copyDate(remoteConn, conn, bufSize)
    go copyDate(conn, remoteConn, bufSize)
}

