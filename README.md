# vproxy

高性能 HTTP/HTTPS 代理服务器，支持上游代理转发、TLS 指纹伪装、HTTP/2、认证、自动证书等功能。

## 特性

- **HTTP / HTTPS 代理**：完整支持普通请求与 `CONNECT` 隧道
- **同端口协议复用**：HTTP 与 HTTPS 可在同一端口监听（TLS 嗅探）
- **上游代理支持**：
  - HTTP / HTTPS
  - SOCKS5 / SOCKS5h（前者本地解析目标域名，后者由代理远程解析）
  - SSH 隧道（默认严格校验 host key）
- **TLS 指纹伪装**：基于 [utls](https://github.com/refraction-networking/utls) 模拟 Chrome ClientHello，可按请求指定浏览器版本
- **HTTP/2 连接池**：自动协商与复用 h2 连接，按 host 分桶，每 host 最多缓存 10 个连接
- **认证**：Basic Auth，支持 `Proxy-Authorization` Header、URL 路径、Query 三种方式
- **证书**：
  - 自定义证书
  - Let's Encrypt 自动申请（autocert）
- **安全防护**：
  - 自环检测（防止代理连自己）
  - 无认证时禁止访问本机任意地址
  - SSH 默认严格校验 host key（无可用 `known_hosts` 时拒绝连接）
- **连接式代理（LinkPosterior）**：支持把目标 URL 嵌入路径或 `@url` 参数
- **可配置日志级别**、缓冲区大小、连接超时等

## 安装

### 从源码构建

```bash
git clone https://github.com/456vv/vproxy.git
cd vproxy
go build -o vproxy ./cmd/main
```

### 直接运行

```bash
go run ./cmd/main -addr 0.0.0.0:8080
```

## 快速开始

```bash
# 最简单启动（本地 8080）
./vproxy -addr 127.0.0.1:8080

# 对外开放 + 开启认证
./vproxy -addr 0.0.0.0:8080 -user admin -pwd 123456

# 开启详细日志
./vproxy -addr 0.0.0.0:8080 -logLevel 7

# 使用上游代理
./vproxy -addr 0.0.0.0:8080 -proxy "socks5://user:pass@1.2.3.4:1080"
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-addr` | `127.0.0.1:8080` | 监听地址 |
| `-user` / `-pwd` | 空 | 认证用户名 / 密码 |
| `-proxy` | 空 | 上游代理地址，支持 `http://`、`https://`、`socks5://`、`socks5h://`、`ssh://`（不支持 `socks4` / `socks`） |
| `-timeout` | `5s` | 转发连接超时（支持 `ns/us/ms/s/m/h`，解析失败会报错退出） |
| `-dataBufioSize` | `10240` | 数据交换缓冲区大小（字节） |
| `-log` | 空 | 日志文件路径（空则输出到控制台） |
| `-logLevel` | `0` | 日志级别：0不记录 1客户端IP 2认证 3Host 4路径 5请求 6响应 7错误 |
| `-linkPosterior` | `false` | 启用连接式代理（目标 URL 写在路径或 `@url` 参数中） |
| `-tlsCertFile` / `-tlsKeyFile` | 空 | 自定义 TLS 证书与密钥 |
| `-autoCertCache` | 空 | 自动证书缓存目录 |
| `-autoCertHost` | 空 | 允许自动申请证书的域名（多个用逗号分隔） |
| `-knownHosts` | 空 | SSH 代理使用的 `known_hosts` 文件（多个用逗号分隔；留空时尝试 `~/.ssh/known_hosts`） |
| `-insecureSSH` | `false` | 跳过 SSH host key 校验（仅调试，有 MITM 风险） |

> **关于 SOCKS5 与 SOCKS5h**：`socks5://` 会在本地解析目标域名后交给代理；`socks5h://` 则把域名原样交给代理远程解析，适合本地 DNS 不可靠或需要远程解析的场景。

## 使用示例

### 1. 带认证的代理

```bash
./vproxy -addr 0.0.0.0:8080 -user myuser -pwd mypass
```

客户端可使用：

```
http://myuser:mypass@proxy-ip:8080
```

也支持在路径或 Query 中传递认证信息（适合某些无法设置 Header 的客户端）：

```
# Query 形式
http://proxy-ip:8080/?@auth=myuser:mypass&@url=https://www.example.com/

# 路径形式（无认证或已通过其他方式认证时）
http://proxy-ip:8080/myuser:mypass@https://www.example.com/
```

> 路径形式与 LinkPosterior 同时使用时，建议优先使用 Header 或 `@auth` Query，避免路径解析歧义。

### 2. 上游 SOCKS5 / HTTP 代理

```bash
# SOCKS5（本地解析目标域名）
./vproxy -addr 0.0.0.0:8080 -proxy "socks5://user:pass@1.2.3.4:1080"

# SOCKS5h（由上游代理远程解析域名）
./vproxy -addr 0.0.0.0:8080 -proxy "socks5h://user:pass@1.2.3.4:1080"

# HTTP 上游
./vproxy -addr 0.0.0.0:8080 -proxy "http://1.2.3.4:8888"

# HTTPS 上游（可跳过证书校验）
./vproxy -addr 0.0.0.0:8080 -proxy "https://1.2.3.4:8443?skipVerify=true"
```

### 3. SSH 上游代理

```bash
./vproxy -addr 0.0.0.0:8080 \
  -proxy "ssh://user:password@ssh-server:22" \
  -knownHosts ~/.ssh/known_hosts
```

> 默认严格校验 host key；若未配置可用的 `known_hosts`，连接会被拒绝（不会静默接受任意 key）。

调试时可临时关闭 host key 校验：

```bash
./vproxy -addr 0.0.0.0:8080 \
  -proxy "ssh://user:password@ssh-server:22" \
  -insecureSSH
```

### 4. TLS 服务端（自定义证书）

```bash
./vproxy -addr 0.0.0.0:443 \
  -tlsCertFile /path/to/cert.pem \
  -tlsKeyFile /path/to/key.pem
```

### 5. 自动申请 Let's Encrypt 证书

```bash
./vproxy -addr 0.0.0.0:443 \
  -autoCertCache ./certs \
  -autoCertHost "proxy.example.com,www.proxy.example.com"
```

### 6. 连接式代理（LinkPosterior）

启用后可通过路径或 `@url` 参数直接指定目标：

```bash
./vproxy -addr 0.0.0.0:8080 -linkPosterior
```

访问示例：

```
http://proxy-ip:8080/https://www.example.com/path/to/file
http://proxy-ip:8080/?@url=https://www.example.com/abc&@auth=user:pass
```

### 7. 跳过目标站点证书校验 / 指定浏览器指纹

在请求 Query 中添加参数（仅对本请求生效）：

```
http://proxy/https://example.com?@skipVerify=true
http://proxy/https://example.com?@browserVer=120
```

> `@browserVer` 需为 utls 支持的浏览器版本标识，使用未知版本可能导致握手失败，请谨慎使用。

## 架构简述

```
客户端
  │
  ▼
protocolMuxListener（嗅探 TLS / 明文 HTTP）
  │
  ▼
http.Server
  │
  ├─ CONNECT  → proxyConnect（隧道转发）
  └─ 普通请求 → proxyHTTP
                  ├─ H2 连接池复用（按 host 分桶，上限 10）
                  ├─ utls 指纹握手
                  └─ 上游代理（HTTP/SOCKS5/SSH）
```

## 注意事项

1. **无认证时禁止访问本机**：为防止 SSRF，未设置 `-user` 时无法访问 `localhost`、`127.0.0.1`、本机网卡 IP 等任意本机地址。
2. **自环保护**：即使开启认证，也不允许目标地址指向代理自身监听地址与端口，避免递归拨号耗尽连接。
3. **SSH 安全**：默认严格校验 host key，无可用 `known_hosts` 时拒绝连接。生产环境请配置正确的 `known_hosts`，不要使用 `-insecureSSH`。
4. **上游代理协议**：仅支持 HTTP / HTTPS / SOCKS5 / SOCKS5h / SSH；`socks4` / `socks` 不被支持。
5. **缓冲区**：高并发或大文件场景可适当调大 `-dataBufioSize`。
6. **LinkPosterior 与认证**：启用认证时，路径形式的链接代理可能与路径认证解析冲突，建议使用 `@auth` Query 或 `Proxy-Authorization` Header。
7. **`@browserVer` 风险**：传入 utls 不支持的版本标识可能导致握手失败，请先在测试环境验证。

## License

Apache 2.0