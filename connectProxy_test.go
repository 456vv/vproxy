package vproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/issue9/assert/v4"
)

func Test_connectProxy_ServeHTTP(t *testing.T) {
	as := assert.New(t, true)
	tests := []struct {
		method string
		addr   string
		url    string
	}{
		{method: http.MethodConnect, addr: "www.baidu.com:80", url: "http://www.baidu.com/index.html"},
	}

	cp := &proxyConnect{
		proxy: &Proxy{
			ErrorLog:      log.New(os.Stdout, "", log.LstdFlags),
			ErrorLogLevel: Error,
			DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
				return net.Dial(network, address)
			},
		},
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(cp.ServeHTTP),
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	as.NotError(err)
	defer l.Close()

	laddr := l.Addr().String()
	fmt.Println("服务器IP: ", laddr)
	go srv.Serve(l)
	time.Sleep(time.Second * 2)

	for _, test := range tests {
		// 连接代理服务器
		netConn, err := net.Dial("tcp", laddr)
		as.NotError(err)

		// 要求代理服务器连接到WEB服务器
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: test.addr},
			Host:   test.addr,
			Header: make(http.Header),
		}
		err = req.Write(netConn)
		as.NotError(err)
		br := bufio.NewReader(netConn)
		res, err := http.ReadResponse(br, req)
		as.NotError(err)
		as.Equal(res.Status, "200 Connection established")

		// 请求代理服务器转发到WEB服务器
		req, err = http.NewRequest("GET", test.url, nil)
		as.NotError(err)
		req.Header.Add("Connection", "Close")
		err = req.Write(netConn)
		as.NotError(err)

		res, err = http.ReadResponse(br, req)
		as.NotError(err)

		as.Equal(res.StatusCode, http.StatusOK)
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		netConn.Close()
	}
}
