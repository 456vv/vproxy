package vproxy

import (
	"testing"
    "time"
    //"net"
    "net/http"
    "fmt"
    //"net/url"
)

func Test_Proxy_0(t *testing.T) {

    c := &Config{
        DataBufioSize:1024,
        Auth: func(username, password string) bool{
            return true
        },
    }
    p := &Proxy{
        Addr        : "127.0.0.1:1101",
        Transport   : &http.Transport{
            //Proxy: func(req *http.Request) (*url.URL, error){
            //    return req.URL, nil
            //},
            //Dial: func(network, addr string) (net.Conn, error){
            //    return net.Dial(network, "127.0.0.1:8118")
            //},
        //    DialTLS: func(network, addr string) (net.Conn, error),
        //    TLSClientConfig: *tls.Config,
        //    DisableKeepAlives: bool,
        //    DisableCompression: bool,
        //    MaxIdleConnsPerHost: int,
        //    ResponseHeaderTimeout: time.Duration,
        //    TLSHandshakeTimeout: time.Duration,
        //    ExpectContinueTimeout: time.Duration,
        //    TLSNextProto: map[string]func(authority string, c *tls.Conn),
        },
        Config      : c,
    }
    go func(){
        fmt.Println("服务器IP：", p.Addr)
        time.Sleep(time.Second*10)
        p.Close()
    }()
    err := p.ListenAndServ()
    if err != nil {
    	t.Logf("%s", err)
    }



}