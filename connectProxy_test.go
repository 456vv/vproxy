package vproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// CONNECT 隧道测试分三类：
//   - 本地隧道：不访问公网，验证 200 与双向转发
//   - 请求校验：缺 Host / 拨号失败
//   - 集成：VPROXY_INTEGRATION=1 时才打真实站点

func newConnectProxy(dial func(ctx context.Context, network, address string) (net.Conn, error)) *proxyConnect {
	return newProxyConnect(&Proxy{
		DataBufioSize: 4 << 10,
		DialContext:   dial,
	})
}

// startRawHTTP 是只应答一次 GET 的本地上游，避免依赖 baidu。
func startRawHTTP(t *testing.T, body string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func serveConnect(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// 分类：本地隧道
func TestConnectProxy_LocalTunnel(t *testing.T) {
	const body = "tunnel-ok"
	upstream := startRawHTTP(t, body)
	cp := newConnectProxy(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != upstream {
			t.Errorf("dial address = %s, want %s", address, upstream)
		}
		return net.Dial(network, address)
	})
	laddr := serveConnect(t, cp)

	conn, err := net.Dial("tcp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := &http.Request{
		Method: http.MethodConnect,
		// Host 必须在 URL 上：ServeHTTP 以 req.URL.Host 为准，只写 Opaque 会被当成路径错误。
		URL:    &url.URL{Scheme: "http", Host: upstream},
		Host:   upstream,
		Header: make(http.Header),
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "200 Connection established" {
		t.Fatalf("status = %q", res.Status)
	}

	get, err := http.NewRequest(http.MethodGet, "http://"+upstream+"/index.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	get.Host = upstream
	get.Header.Set("Connection", "close")
	if err := get.Write(conn); err != nil {
		t.Fatal(err)
	}
	res, err = http.ReadResponse(br, get)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d", res.StatusCode)
	}
	got, _ := io.ReadAll(res.Body)
	if string(got) != body {
		t.Fatalf("body = %q", got)
	}
}

// 分类：请求校验
func TestConnectProxy_Rejects(t *testing.T) {
	t.Run("empty host", func(t *testing.T) {
		cp := newConnectProxy(func(ctx context.Context, network, address string) (net.Conn, error) {
			t.Fatal("should not dial")
			return nil, nil
		})
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{},
			Header: make(http.Header),
		}
		rr := httptest.NewRecorder()
		cp.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, body = %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("dial error", func(t *testing.T) {
		cp := newConnectProxy(func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("dial refused")
		})
		req := &http.Request{
			Method:     http.MethodConnect,
			URL:        &url.URL{Host: "example.com:443", Scheme: "https"},
			Host:       "example.com:443",
			Header:     make(http.Header),
			RequestURI: "example.com:443",
		}
		rr := httptest.NewRecorder()
		cp.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("code = %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "dial refused") {
			t.Fatalf("body = %s", rr.Body.String())
		}
	})
}

// 分类：双向拷贝能在客户端关闭后退出（真实 TCP，不用 net.Pipe）
func TestConnectProxy_ExitsOnClientClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()

	cp := newConnectProxy(func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, ln.Addr().String())
	})
	laddr := serveConnect(t, cp)

	conn, err := net.Dial("tcp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: "example.com:443", Scheme: "https"},
		Host:   "example.com:443",
		Header: make(http.Header),
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %s", res.Status)
	}
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, br)
		close(done)
	}()
	conn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel did not finish after client close")
	}
}
