# vproxy [![Build Status](https://travis-ci.org/456vv/vproxy.svg?branch=master)](https://travis-ci.org/456vv/vproxy)
golang vproxy, HTTP/HTTPS proxy server, HTTP/HTTPS 代理服务器

命令行：
-----------------------------------
  -Backstage
        后台启动进程
  -addr string
        代理服务器地 (format "0.0.0.0:8080")
  -dataBufioSize int
        代理数据交换缓冲区大小，单位字节 (default 10240)
  -disableCompression
        禁止传送数据时候进行压缩 (default false)
  -disableKeepAlives
        禁止长连接 (default false)
  -expectContinueTimeout int
        http1.1过度到http2的等待超时，单位毫秒 (default 1000)
  -idleConnTimeout int
        空闲连接超时时，单位毫秒 (default 0)
  -keepAlive int
        保持连接心跳检测超时，单位毫秒 (default 30000)
  -log string
        日志文件(默认留空在控制台显示日志)  (format "./vproxy.txt")
  -logLevel int
        日志级别，0)不记录 1)客户端IP 2)认证 3)访问的Host地址 4)路径 5)请求 6)响应 7)错误 (default 0)
  -maxIdleConns int
        保持空闲连接(TCP)数量 (default 500)
  -maxIdleConnsPerHost int
        保持空闲连接(Host)数量 (default 500)
  -maxResponseHeaderBytes int
        读取服务器发来的文件标头大小限制 (default 0)
  -proxy string
        代理服务器的上级代理IP地址 (format "11.22.33.44:8888")
  -pwd string
        密码
  -responseHeaderTimeout int
        读取服务器发来的文件标头超时，单位毫秒 (default 0)
  -timeout int
        转发连接请求超时，单位毫秒 (default 30000)
  -tlsHandshakeTimeout int
        SSL握手超时，单位毫秒 (default 10000)
  -user string
        用户名

命令行例子：vproxy -addr 0.0.0.0:8080


列表：
-----------------------------------
# **列表：**
```go
const defaultDataBufioSize    = 1<<20                                            // 默认数据缓冲1MB
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
type Config struct {                                                     // 配置
    DataBufioSize     int                                                        // 缓冲区大小
    Auth              func(username, password string) bool                       // 认证
    Timeout           time.Duration                                              // 转发连接请求超时
    Deadline          time.Time                                                  // 转发连接请求超时
}
type Proxy struct {                                                      // 代理
    *Config                                                                      // 配置
    Addr        string                                                           // 代理IP地址
    Server      http.Server                                                      // 服务器
    Transport   http.RoundTripper                                                // 代理
    ErrorLogLevel LogLevel                                                       // 日志级别
    ErrorLog    *log.Logger                                                      // 日志
    l           net.Listener                                                     // 连接对象
}
    func (p *Proxy) setDefault()                                                 // 设置默认
    func (p *Proxy) initServer() *http.Server                                    // 初始化服务器
    func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request)         // 处理
    func (p *Proxy) ListenAndServ() error                                        // 监听
    func (p *Proxy) Serve(l net.Listener) error                                  // 监听
    func (p *Proxy) Close() error                                                // 关闭代理
```