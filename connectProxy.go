package vproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
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
		if strings.HasPrefix(rh, "[") && strings.HasSuffix(rh, "]") {
			rh = rh[1 : len(rh)-1]
		}
		rp = "80"
		if scheme == "https" {
			rp = "443"
		}
	}
	return net.JoinHostPort(rh, rp)
}

func (T *proxyConnect) resErr(rw http.ResponseWriter, err error) {
	T.proxy.resErr(rw, err)
}

func (T *proxyConnect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodConnect {
		T.proxy.logf(Error, "HTTP method is not %s", http.MethodConnect)
		http.Error(rw, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	remoteAddr := host2addr(req.URL.Host, req.URL.Scheme)
	ctx := context.Background()

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
		T.resErr(rw, err)
		return
	}

	hj, ok := rw.(http.Hijacker)
	if !ok {
		T.resErr(rw, errors.New("http.ResponseWriter does not implement http.Hijacker"))
		rConn.Close()
		return
	}
	lConn, lrw, err := hj.Hijack()
	if err != nil {
		T.resErr(rw, err)
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
