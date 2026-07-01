package vproxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"time"
)

// protocolMuxListener 实现了 net.Listener 接口，用于在同一个连接上嗅探 HTTP/HTTPS 协议
type protocolMuxListener struct {
	net.Listener
	tlsConfig *tls.Config
}

// Accept 覆盖了标准的 Accept 方法，实现协议分发
func (l *protocolMuxListener) Accept() (net.Conn, error) {
	for {
		// 1. 接受底层连接
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		if l.tlsConfig == nil {
			// 如果没有 TLS 配置，直接返回普通连接
			return conn, nil
		}

		// 设置读取截止时间，防止阻塞过久
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			conn.Close()
			continue
		}

		// 2. 包装连接以便我们可以“偷看”前几个字节
		reader := bufio.NewReader(conn)

		// 3. 偷看前 5 个字节
		peeked, err := reader.Peek(5)
		if err != nil {
			// 如果连接失效或读取超时，直接关闭连接继续等待下一个，避免使主 Listener 崩溃
			conn.Close()
			continue
		}

		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			conn.Close()
			continue
		}

		bc := &bufferConn{
			Conn: conn,
			br:   reader,
		}

		// 4. 判断协议类型
		// TLS 握手消息的起始字节 (0x16)
		if len(peeked) >= 1 && peeked[0] == 0x16 {
			// 创建一个包装器，将偷看的数据重新放回流中
			tlsConn := tls.Server(bc, l.tlsConfig)
			return tlsConn, nil
		}

		// 创建一个包装器，将偷看的数据重新放回流中，供标准 HTTP 处理器读取
		return bc, nil
	}
}
