package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/456vv/vconn"
	"github.com/456vv/vproxy"
	"golang.org/x/crypto/ssh"

	"golang.org/x/crypto/acme/autocert"
)

var (
	flog             = flag.String("log", "", "日志文件(默认留空在控制台显示日志)  (format \"./vproxy.txt\")")
	ftlsCertFile     = flag.String("tlsCertFile", "", "SSl证书文件(自定义证书)")
	ftlsKeyFile      = flag.String("tlsKeyFile", "", "SSl密钥文件(自定义证书)")
	fautoCertCache   = flag.String("autoCertCache", "", "ssl自动申请证书缓存目录(自动证书)")
	fautoCertHost    = flag.String("autoCertHost", "", "ssl允许自动申请证书host地址，多个用逗号分隔(自动证书)")
	fuser            = flag.String("user", "", "用户名")
	fpwd             = flag.String("pwd", "", "密码")
	flogLevel        = flag.Int("logLevel", 0, "日志级别，0)不记录 1)客户端IP 2)认证 3)访问的Host地址 4)路径 5)请求 6)响应 7)错误 (default 0)")
	faddr            = flag.String("addr", "127.0.0.1:8080", "代理服务器地址 (format \"0.0.0.0:8080\")")
	fproxy           = flag.String("proxy", "", "代理服务器的上级代理IP地址 (format \"http://11.22.33.44:8888\" or \"socks5://admin:admin@11.22.33.44:1080\")")
	fidleConnTimeout = flag.Int64("idleConnTimeout", 0, "空闲连接超时时，单位毫秒 (default 0)")
	fdataBufioSize   = flag.Int("dataBufioSize", 1024*10, "代理数据交换缓冲区大小，单位字节")
	ftimeout         = flag.Int64("timeout", 300000, "转发连接请求超时，单位毫秒")
	flinkPosterior   = flag.Bool("linkPosterior", false, "支持连接式代理，如：http://111.222.333.444:8080/?@auth=user:pass&@url=https://www.baidu.com/abc/file.zip")
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
		out = file
	}

	p := &vproxy.Proxy{
		LinkPosterior: *flinkPosterior,
		DataBufioSize: *fdataBufioSize,
		Addr:          *faddr,
		ErrorLogLevel: vproxy.LogLevel(*flogLevel),
		Tr:            http.DefaultTransport,
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

	p.ErrorLog = log.New(out, "", log.Lshortfile|log.LstdFlags)
	if *fuser != "" {
		p.Auth = func(username, password string) bool {
			return username == *fuser && password == *fpwd
		}
	}

	tr := p.Tr.(*http.Transport)
	tr.IdleConnTimeout = time.Duration(*fidleConnTimeout) * time.Millisecond
	dialer := &net.Dialer{
		Timeout:   time.Duration(*ftimeout) * time.Millisecond,
		DualStack: true,
	}
	p.DialContext = dialer.DialContext

	if *fproxy != "" {
		purl, err := url.Parse(*fproxy)
		if err != nil {
			fmt.Println("上级代理格式错误：", err)
			return
		}

		tr.Proxy = func(r *http.Request) (*url.URL, error) {
			return purl, nil
		}

		var puser, ppwd string
		if purl.User != nil {
			puser = purl.User.Username()
			ppwd, _ = purl.User.Password()
		}

		switch purl.Scheme {
		case "ssh":
			config := &ssh.ClientConfig{
				User: puser,
				Auth: []ssh.AuthMethod{
					ssh.Password(ppwd),
				},
				HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					log.Println(hostname, remote, key)
					return nil
				},
				HostKeyAlgorithms: []string{
					ssh.KeyAlgoRSA,
					ssh.KeyAlgoDSA,
					ssh.KeyAlgoECDSA256,
					ssh.KeyAlgoSKECDSA256,
					ssh.KeyAlgoECDSA384,
					ssh.KeyAlgoECDSA521,
					ssh.KeyAlgoED25519,
					ssh.KeyAlgoSKED25519,
				},
				Timeout: 10 * time.Second,
			}

			var (
				sshConnect bool
				dialMux    sync.Mutex
				sshConn    net.Conn
				client     *ssh.Client
			)
			sshReconn := func() error {
				dialMux.Lock()
				defer dialMux.Unlock()
				if sshConnect {
					return nil
				}

				sshConn, client, err = sshDial("tcp", purl.Host, config)
				if err != nil {
					return err
				}
				sshConnect = true
				go func() {
					if cn, ok := sshConn.(vconn.CloseNotifier); ok {
						err := <-cn.CloseNotify()
						log.Println(err)
						client.Close()
						sshConnect = false
					}
				}()
				return nil
			}
			err = sshReconn()
			if err != nil {
				fmt.Println("代理拨号错误: ", err)
				return
			}

			tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if !sshConnect {
					err := sshReconn()
					if err != nil {
						return nil, err
					}
				}
				return client.Dial(network, address)
			}
		case "https":
			colonPos := strings.LastIndex(purl.Host, ":")
			if colonPos == -1 {
				colonPos = len(purl.Host)
			}
			hostname := purl.Host[:colonPos]
			tlsconfig := &tls.Config{
				ServerName:         hostname,         // 证书验证
				MinVersion:         tls.VersionTLS12, // 最低版本TLS1.2
				InsecureSkipVerify: false,            // 忽略证书验证
			}
			if purl.Query().Get("skipVerify") == "true" {
				tlsconfig.InsecureSkipVerify = true // 忽略证书验证
			}

			// connectProxy
			tr.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				pconn, err := p.DialContext(ctx, network, purl.Host)
				if err != nil {
					return nil, err
				}
				// 建立到代理服务器的ssl连接
				tconn := tls.Client(pconn, tlsconfig)
				return tconn, nil
			}
		default:
		}
	}

	defer p.Close()
	err := p.ListenAndServe()
	if err != nil {
		log.Printf("vproxy-Error：%s", err)
	}
}

func sshDial(network, addr string, config *ssh.ClientConfig) (net.Conn, *ssh.Client, error) {
	conn, err := net.DialTimeout(network, addr, config.Timeout)
	if err != nil {
		return nil, nil, err
	}

	conn = vconn.NewConn(conn)
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, nil, err
	}

	return conn, ssh.NewClient(c, chans, reqs), nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
