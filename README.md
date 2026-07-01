# vproxy
vproxy是一个命令行工具，支持HTTP/HTTPS协议代理服务器。

命令行：
-----------------------------------

命令行例子：vproxy -addr 0.0.0.0:8080
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

```
