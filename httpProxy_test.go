package vproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/issue9/assert/v4"
)

func Test_httpProxy_ServeHTTP(t *testing.T) {
	as := assert.New(t, true)
	tests := []struct {
		method     string
		addr       string
		url        string
		req        string
		statusCode int
	}{
		{req: "GET http://www.baidu.com/index.html HTTP/1.1\r\nHost:abcdef\r\nConnection:Keep-Alive\r\n\r\n", statusCode: 200},
		{req: "GET https://www.baidu.com/ HTTP/1.1\r\nHost:www.baidu.com\r\nConnection:Keep-Alive\r\n\r\n", statusCode: 200},
		{req: "GET /index.html?123 HTTP/1.1\r\nHost:www.baidu.com\r\nConnection:Keep-Alive\r\n\r\n", statusCode: 200},
		{req: "GET https://kyfw.12306.cn/ HTTP/1.1\r\nHost:kyfw.12306.cn\r\nConnection:Keep-Alive\r\n\r\n", statusCode: 302},
	}

	// 服务器
	hp := newProxyHTTP(&Proxy{
		DataBufioSize: 1024,
		DialContext:   defaultDial.DialContext,
	})

	srv := &http.Server{
		Handler: http.HandlerFunc(hp.ServeHTTP),
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	as.NotError(err)
	defer l.Close()
	laddr := l.Addr().String()
	fmt.Println("服务器IP: ", laddr)

	go srv.Serve(l)
	time.Sleep(time.Second * 2)

	for _, test := range tests {
		netConn, err := net.Dial("tcp", laddr)
		as.NotError(err)

		req, err := http.ReadRequest(bufio.NewReader(bytes.NewBufferString(test.req)))
		as.NotError(err)
		req.WriteProxy(netConn)

		br := bufio.NewReader(netConn)
		res, err := http.ReadResponse(br, &http.Request{})
		as.NotError(err)
		as.Equal(res.StatusCode, test.statusCode)
		io.Copy(io.Discard, res.Body)
		netConn.Close()
	}
}
