package main

import (
	"github.com/456vv/vproxy"
	"github.com/456vv/vsocks5"
	"github.com/456vv/vconn"
    "golang.org/x/crypto/ssh"
    "net"
    "net/http"
    "crypto/tls"
    "net/url"
    "time"
    "flag"
    "fmt"
    "log"
    "io"
    "os"
    "context"
    "bytes"
    "errors"
    "encoding/base64"
)

var (
    flog = flag.String("log", "", "日志文件(默认留空在控制台显示日志)  (format \"./vproxy.txt\")")
    ftlsCertFile = flag.String("tlsCertFile", "", "SSl证书文件")
    ftlsKeyFile = flag.String("tlsKeyFile", "", "SSl密钥文件")
    fuser = flag.String("user", "", "用户名")
    fpwd = flag.String("pwd", "", "密码")
    flogLevel = flag.Int("logLevel", 0, "日志级别，0)不记录 1)客户端IP 2)认证 3)访问的Host地址 4)路径 5)请求 6)响应 7)错误 (default 0)")
    faddr = flag.String("addr", "", "代理服务器地 (format \"0.0.0.0:8080\")")
    fproxy = flag.String("proxy", "", "代理服务器的上级代理IP地址 (format \"http://11.22.33.44:8888\" or \"socks5://admin:admin@11.22.33.44:1080\")")
    fidleConnTimeout = flag.Int64("idleConnTimeout", 0, "空闲连接超时时，单位毫秒 (default 0)")
    fdataBufioSize = flag.Int("dataBufioSize", 1024*10, "代理数据交换缓冲区大小，单位字节")
    ftimeout = flag.Int64("timeout", 300000, "转发连接请求超时，单位毫秒")
    flinkPosterior = flag.Bool("linkPosterior", false, "支持连接式代理，如：http://111.222.333.444:8080/?auth=user:pass&url=https://www.baidu.com/abc/file.zip")
)

func main(){
    flag.Parse()
    if flag.NFlag() == 0 {
        flag.PrintDefaults()
        fmt.Println("\r\n命令行例子：vproxy -addr 0.0.0.0:8080")
        return
    }
    var out io.Writer = os.Stdout
    if *flog != "" {
        file, err := os.OpenFile(*flog, os.O_CREATE | os.O_RDWR, 0777)
        if err != nil {
            fmt.Println(err)
            return
        }
        out = file
    }
    
	p := &vproxy.Proxy{
    	LinkPosterior: *flinkPosterior,
        DataBufioSize: *fdataBufioSize,
        Addr        : *faddr,
        ErrorLogLevel: vproxy.LogLevel(*flogLevel),
    }
    if *ftlsCertFile != "" && *ftlsKeyFile != "" {
    	cert, err := tls.LoadX509KeyPair(*ftlsCertFile, *ftlsKeyFile)
    	if err != nil {
    		fmt.Println(err)
    		return
    	}
    	tlsConf := new(tls.Config)
        tlsConf.Certificates = []tls.Certificate{cert}
    	tlsConf.BuildNameToCertificate()
    	p.Server.TLSConfig = tlsConf
    }
    p.ErrorLog = log.New(out, "", log.Lshortfile|log.LstdFlags)
    if *fuser != "" {
        p.Auth = func(username, password string) bool {
            return username == *fuser && password == *fpwd
        }
     }
	
    tr := http.DefaultTransport.(*http.Transport)
    tr.IdleConnTimeout=time.Duration(*fidleConnTimeout) * time.Millisecond
	dialer := &net.Dialer{
		Timeout:   time.Duration(*ftimeout) * time.Millisecond,
		DualStack: true,
	}
	p.DialContext=dialer.DialContext
	
	if *fproxy != "" {
		purl, err := url.Parse(*fproxy)
		if err != nil {
			fmt.Println("上级代理格式错误：", err)
			return
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
					ssh.KeyAlgoECDSA384,
					ssh.KeyAlgoECDSA521,
					ssh.KeyAlgoED25519,
				},
				Timeout: 5 * time.Second,
			}
			
			sshConn, client, err := sshDial("tcp", purl.Host, config)
			if err != nil {
				fmt.Println("代理拨号错误: ", err)
		        return
			}
			defer func(){
				client.Close()
			}()
			
		    //connectProxy
			p.DialContext = func(ctx context.Context, network, address string) (net.Conn, error){
				if cn, ok := sshConn.(vconn.CloseNotifier); ok {
					select {
					case <-cn.CloseNotify():
						sshConn, client, err = sshDial("tcp", purl.Host, config)
						if err != nil {
							return nil, err
						}
					default:
					}
				}
				
				return client.Dial(network, address)
			}
			
			//httpProxy
			tr.DialContext=p.DialContext
		case "https","http":
			//httpProxy
		    tr.Proxy = func(r *http.Request) (*url.URL, error){
		        return purl, nil
		    }
		    
		    //connectProxy
			p.DialContext = func(ctx context.Context, network, address string) (net.Conn, error){
				pconn, err := dialer.Dial(network, purl.Host)
				if err != nil {
					return nil, err
				}
				
				if purl.Scheme == "http" {
					return pconn, err
				}
				
				var pauth string
				if puser != "" {
					pauth = "\nProxy-Authorization: Basic " +basicAuth(puser, ppwd)
				}
				pconn.Write([]byte(fmt.Sprintf("CONNECT %[1]s HTTP/1.1\r\nHost: %[1]s%s\r\n\r\n", address, pauth)))
				
				p := make([]byte, 1024)
				n, err := pconn.Read(p)
				if err != nil {
					return nil, err
				}
				if bytes.Compare([]byte("HTTP/1.1 200 Connection established"), p[:n]) != 0 {
					pconn.Close()
					return nil, errors.New("https proxy not support")
				}
				return pconn, err
			}
		case "socks5":
			//httpProxy
		    tr.Proxy = func(r *http.Request) (*url.URL, error){
		        return purl, nil
		    }
		    
		    //connectProxy
			s5Client := &vsocks5.Client{
				Username: puser,
				Password: ppwd,
				Server: purl.Host,
			}
			p.DialContext = func(ctx context.Context, network, address string) (net.Conn, error){
				return s5Client.Dial(network, address)
			}
		default:
			fmt.Printf("暂时不支持 %s 协议代理！\n", purl.Scheme)
			return
		}
	}
	
   	defer p.Close()
    err := p.ListenAndServe()
    if err != nil {
        log.Printf("vproxy-Error：%s", err)
    }


}
func sshDial(network, addr string, config *ssh.ClientConfig) (net.Conn, *ssh.Client, error){
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
