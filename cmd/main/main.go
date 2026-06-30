package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/456vv/vproxy"

	"golang.org/x/crypto/acme/autocert"
)

var (
	flog           = flag.String("log", "", "日志文件(默认留空在控制台显示日志)  (format \"./vproxy.txt\")")
	ftlsCertFile   = flag.String("tlsCertFile", "", "SSl证书文件(自定义证书)")
	ftlsKeyFile    = flag.String("tlsKeyFile", "", "SSl密钥文件(自定义证书)")
	fautoCertCache = flag.String("autoCertCache", "", "ssl自动申请证书缓存目录(自动证书)")
	fautoCertHost  = flag.String("autoCertHost", "", "ssl允许自动申请证书host地址，多个用逗号分隔(自动证书)")
	fuser          = flag.String("user", "", "用户名")
	fpwd           = flag.String("pwd", "", "密码")
	flogLevel      = flag.Int("logLevel", 0, "日志级别，0)不记录 1)客户端IP 2)认证 3)访问的Host地址 4)路径 5)请求 6)响应 7)错误 (default 0)")
	faddr          = flag.String("addr", "127.0.0.1:8080", "代理服务器地址 (format \"0.0.0.0:8080\")")
	fproxy         = flag.String("proxy", "", "代理服务器的上级代理IP地址 (format \"http://11.22.33.44:8888\" or \"socks5://admin:admin@11.22.33.44:1080\")")
	fdataBufioSize = flag.Int("dataBufioSize", 1024*10, "代理数据交换缓冲区大小，单位字节")
	ftimeout       = flag.String("timeout", "5s", "转发连接请求超时，单位：ns, us, ms, s, m, h")
	flinkPosterior = flag.Bool("linkPosterior", false, "支持连接式代理，如：http://111.222.333.444:8080/?@auth=user:pass&@url=https://www.baidu.com/abc/file.zip")
)

func main() {
	flag.Parse()
	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		fmt.Println("\r\n命令行例子：vproxy -addr 0.0.0.0:8080")
		return
	}
	var out io.Writer = os.Stdout
	if *flog != "" {
		file, err := os.OpenFile(*flog, os.O_CREATE|os.O_RDWR, 0o777)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()
		out = file
	}

	p := &vproxy.Proxy{
		LinkPosterior: *flinkPosterior,
		DataBufioSize: *fdataBufioSize,
		Addr:          *faddr,
		ErrorLogLevel: vproxy.LogLevel(*flogLevel),
		ErrorLog:      log.New(out, "", log.Lshortfile|log.LstdFlags),
	}

	tlsconf := new(tls.Config)
	if *ftlsCertFile != "" && *ftlsKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(*ftlsCertFile, *ftlsKeyFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		tlsconf.Certificates = []tls.Certificate{cert}
		p.Server.TLSConfig = tlsconf
	}

	if *fautoCertCache != "" && *fautoCertHost != "" {
		if _, err := os.Stat(*fautoCertCache); os.IsNotExist(err) {
			err = os.MkdirAll(*fautoCertCache, 0o777)
			if err != nil {
				fmt.Println(err)
				return
			}
		}
		p.Server.TLSConfig = tlsconf
		p.CertManager = &autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			RenewBefore: time.Hour * 7 * 24, // 7天
			Cache:       autocert.DirCache(*fautoCertCache),
			HostPolicy:  autocert.HostWhitelist(strings.Split(*fautoCertHost, ",")...),
		}
	}

	if *fuser != "" {
		p.Auth = func(username, password string) bool {
			return username == *fuser && password == *fpwd
		}
	}

	dialer := &net.Dialer{
		DualStack: true,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     0,
			Interval: 0,
			Count:    0,
		},
	}
	if *ftimeout != "" {
		if d, err := time.ParseDuration(*ftimeout); err == nil {
			dialer.Timeout = d
		}
	}
	p.DialContext = dialer.DialContext

	if *fproxy != "" {
		p.ProxyURL = func(r *http.Request) (*url.URL, error) {
			return url.Parse(*fproxy)
		}
	}

	defer p.Close()
	err := p.ListenAndServe()
	if err != nil {
		log.Printf("vproxy-Error：%s", err)
	}
}
