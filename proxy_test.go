package vproxy

import (
	"testing"
    "time"
    //"net"
    "fmt"
    //"net/url"
)

func Test_Proxy_0(t *testing.T) {

    p := &Proxy{
        Addr        : "127.0.0.1:0",
        DataBufioSize:1024,
        Auth: func(username, password string) bool{
            return true
        },
    }
    go func(){
        fmt.Println("服务器IP：", p.Addr)
        time.Sleep(time.Second*3)
        p.Close()
    }()
    err := p.ListenAndServe()
    if err != nil {
    	t.Logf("%s", err)
    }



}