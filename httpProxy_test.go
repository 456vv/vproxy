package vproxy

import (
	"testing"
    "net"
    "net/http"
    "bufio"
    "time"
    "fmt"
)
func Test_httpProxy_ServeHTTP(t *testing.T) {
    tests := []struct{
        req string
        statusCode int
    }{
        {req:"GET http://www.baidu.com:80/ HTTP/1.1\r\nHost:abcdef\r\nConnection:Keep-Alive\r\n\r\n", statusCode:200},
        {req:"GET /index.html?123 HTTP/1.1\r\nHost:www.baidu.com:80\r\nConnection:Keep-Alive\r\n\r\n", statusCode:200},
        {req:"GET https://www.baidu.com/ HTTP/1.1\r\nHost:abcdef\r\nConnection:Keep-Alive\r\n\r\n", statusCode:200},
        {req:"GET https://kyfw.12306.cn/ HTTP/1.1\r\nHost:kyfw.12306.cn\r\nConnection:Keep-Alive\r\n\r\n", statusCode:302},
    }

    //服务器
    //tlsConfig := &tls.Config{}
    hp := &proxyHTTP{
        Proxy : &Proxy{
        	DataBufioSize:1024,
        	tr: http.DefaultTransport,
       },
    }
    //hp.Proxy.tr= &http.Transport{
    //	//Proxy: func(*Request) (*url.URL, error), Dial: func(network, addr string) (net.Conn, error),
    //    DialTLS: func(network, addr string) (net.Conn, error){
    //        ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second*3))
    //        defer cancel()
	//		rc, err := new(net.Dialer).DialContext(ctx, "tcp", addr)
	//		if err != nil {
	//			return nil, err
	//		}
    //        host, _, _ := net.SplitHostPort(addr)
    //        tlsConfig.ServerName = host
	//		return tls.Client(rc, tlsConfig), nil
    //    },
    //    TLSClientConfig: tlsConfig,
    //    TLSHandshakeTimeout: time.Second*3,
    //}
    srv := &http.Server{
        Handler: http.HandlerFunc(hp.ServeHTTP),
    }
    l, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    defer l.Close()
    laddr := l.Addr().String()
    fmt.Println("服务器IP: ", laddr)

    go srv.Serve(l)
    time.Sleep(time.Second*2)

    for _, test := range tests {
        netConn, err := net.Dial("tcp", laddr)
        if err != nil {
            t.Fatalf("连接 %s 地址发生错误：%s", laddr, err)
        }
        defer netConn.Close()
        netConn.Write([]byte(test.req))
        httpResponse, err := http.ReadResponse(bufio.NewReader(netConn), &http.Request{})
        if err != nil {
            t.Fatalf("连接 %s 地址，返回内容发生错误：%s", test.req, err)
        }
        defer httpResponse.Body.Close()
        if httpResponse.StatusCode != test.statusCode {
            t.Fatalf("连接 %s 地址，返回状态码不是200，是：%d", test.req, httpResponse.StatusCode)
        }
    }


}