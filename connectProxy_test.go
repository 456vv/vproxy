package vproxy

import (
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	//"net/url"
	"bufio"
	"bytes"
	"fmt"
	"log"
	"time"
)

func Test_connectProxy_ServeHTTP(t *testing.T) {
	tests := []struct {
		req    string
		access string
	}{
		{req: "CONNECT www.baidu.com:80 HTTP/1.0\r\nHost:www.baidu.com:80\r\n\r\n", access: "GET / HTTP/1.1\r\nHost:www.baidu.com\r\nConnection:Close\r\n\r\n"},
		{req: "CONNECT www.baidu.com:80 HTTP/1.1\r\nHost:www.baidu.com:80\r\n\r\n", access: "GET / HTTP/1.1\r\nHost:www.baidu.com\r\nConnection:Close\r\n\r\n"},
	}

	cp := &proxyConnect{
		Proxy: &Proxy{
			ErrorLog:      log.New(os.Stdout, "", log.LstdFlags),
			ErrorLogLevel: Error,
			DataBufioSize: 1024,
		},
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(cp.ServeHTTP),
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	laddr := l.Addr().String()
	fmt.Println("服务器IP: ", laddr)
	go srv.Serve(l)
	time.Sleep(time.Second * 2)

	resultStatus200NoCRCL := resultStatus200[:len(resultStatus200)-4]
	for _, test := range tests {
		netConn, err := net.Dial("tcp", laddr)
		if err != nil {
			t.Fatal(err)
		}
		netConn.Write([]byte(test.req))
		bufioReader := bufio.NewReaderSize(netConn, 1024)

		line, _, err := bufioReader.ReadLine()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(line, resultStatus200NoCRCL) {
			t.Fatalf("返回的状态是： %s，实际状态是：%s", line, resultStatus200NoCRCL)
		}
		bufioReader.Reset(netConn)

		netConn.Write([]byte(test.access))

		resp, err := http.ReadResponse(bufioReader, &http.Request{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("返回的状态号不是200，是：%d", resp.StatusCode)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
