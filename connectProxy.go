package vproxy

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type proxyConnect struct {
	proxy *Proxy
}

func newProxyConnect(p *Proxy) *proxyConnect {
	pconn := &proxyConnect{
		proxy: p,
	}
	return pconn
}

func host2addr(host, scheme string) string {
	rh, rp, err := net.SplitHostPort(host)
	if err != nil {
		rh = host
		rp = "443"
		if scheme == "http" {
			rp = "80"
		}
	}
	return net.JoinHostPort(rh, rp)
}

func (T *proxyConnect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Host == "" {
		T.proxy.logf(URI, "连接路径错误: %s", req.RequestURI)
		http.Error(rw, "Connection path error!", http.StatusBadRequest)
		return
	}
	remoteAddr := host2addr(req.URL.Host, req.URL.Scheme)
	ctx := req.Context()

	var (
		rConn net.Conn
		err   error
	)
	if T.proxy.ProxyURL != nil {
		rConn, err = T.proxy.proxyConnect(ctx, req, remoteAddr)
	} else if T.proxy.DialContext != nil {
		rConn, err = T.proxy.DialContext(ctx, "tcp", remoteAddr)
	} else {
		rConn, err = defaultDial.DialContext(ctx, "tcp", remoteAddr)
	}

	if err != nil {
		T.proxy.resErr(rw, err.Error())
		return
	}

	hj, ok := rw.(http.Hijacker)
	if !ok {
		T.proxy.resErr(rw, "http.ResponseWriter does not implement http.Hijacker")
		rConn.Close()
		return
	}
	lConn, lrw, err := hj.Hijack()
	if err != nil {
		T.proxy.resErr(rw, err.Error())
		rConn.Close()
		return
	}

	if _, err := io.WriteString(lrw, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		lConn.Close()
		rConn.Close()
		return
	}
	lrw.Flush()

	lConn.SetDeadline(time.Time{})
	rConn.SetDeadline(time.Time{})
	var wg sync.WaitGroup
	wg.Go(func() {
		copyDate(lrw, rConn, T.proxy.DataBufioSize)
		lConn.Close()
	})
	wg.Go(func() {
		copyDate(rConn, io.NopCloser(lrw), T.proxy.DataBufioSize)
		rConn.Close()
	})
	wg.Wait()
}
