# vproxy [![Build Status](https://travis-ci.org/456vv/vproxy.svg?branch=master)](https://travis-ci.org/456vv/vproxy)
golang proxy, HTTP/HTTPS proxy server, HTTP/HTTPS 代理服务器

命令行：
-----------------------------------
```
-addr string
    代理服务器地 (format "0.0.0.0:8080")
-dataBufioSize int
    代理数据交换缓冲区大小，单位字节 (default 10240)
-idleConnTimeout int
    空闲连接超时时，单位毫秒 (default 0)
-linkPosterior
    支持连接式代理，如：http://111.222.333.444:8080/https://www.baidu.com/abc/file.zip
-log string
    日志文件(默认留空在控制台显示日志)  (format "./vproxy.txt")
-logLevel int
    日志级别，0)不记录 1)客户端IP 2)认证 3)访问的Host地址 4)路径 5)请求 6)响应 7)错误 (default 0)
-proxy string
    代理服务器的上级代理IP地址 (format "http://11.22.33.44:8888" or "socks5://admin:admin@11.22.33.44:1080")
-pwd string
    密码
-timeout int
    转发连接请求超时，单位毫秒 (default 300000)
-tlsCertFile string
    SSl证书文件
-tlsKeyFile string
    SSl密钥文件
-user string
    用户名

命令行例子：vproxy -addr 0.0.0.0:8080
``
列表：
-----------------------------------
```go
type LogLevel int                                                                // 日志级别
const
    OriginAddr LogLevel    = iota+1                                              // 客户端。
    Authenticate                                                                 // 认证
    Host                                                                         // 访问的Host地址
    URI                                                                          // 路径
    Request                                                                      // 请求
    Response                                                                     // 响应
    Error                                                                        // 错误
)

type Proxy struct {                                                      // 代理
    LinkPosterior   bool                                                             // 支持连接后面的，如：http://192.168.2.31/http://www.baidu.com/
    DataBufioSize   int                                                              // 缓冲区大小
    Auth            func(username, password string) bool                             // 认证
    Addr        string                                                               // 代理IP地址
    Server      http.Server                                                          // 服务器
    DialContext func(ctx context.Context, network, address string) (net.Conn, error) // 拨号
    ErrorLog    *log.Logger                                                          // 日志
    ErrorLogLevel LogLevel                                                           // 日志级别
}
    func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request)         // 处理
    func (p *Proxy) ListenAndServe() error                                       // 监听
    func (p *Proxy) Serve(l net.Listener) error                                  // 监听
    func (p *Proxy) Close() error                                                // 关闭代理

```