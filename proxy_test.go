package vproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// 代理核心测试按职责分组：
//   A. 访问控制（无认证禁本机 / 有认证只禁自环）
//   B. isSelfHost
//   C. LinkPosterior 改写后再做访问控制
//   D. copyData
//
// CONNECT / HTTP 转发的端到端用例在 connectProxy_test.go、httpProxy_test.go。

func reqWithLocal(method, host, scheme, remote string, local *net.TCPAddr) *http.Request {
	req := httptest.NewRequest(method, scheme+"://"+host, nil)
	req.Host = host
	req.RemoteAddr = remote
	return req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, local))
}

// ---------- A. 访问控制 ----------

func TestAccess_NoAuthForbidsLocal(t *testing.T) {
	p := &Proxy{}
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	forbidden := []string{
		"127.0.0.1:8080",
		"127.0.0.1:6379",
		"localhost:3000",
		"0.0.0.0:9000",
		"[::1]:8081",
	}
	for _, h := range forbidden {
		t.Run(h, func(t *testing.T) {
			req := reqWithLocal(http.MethodGet, h, "http", "10.0.0.9:5555", local)
			if err := p.checkLocalAccess(req); err == nil {
				t.Fatalf("no-auth target %q should be forbidden", h)
			}
		})
	}
	t.Run("external allowed", func(t *testing.T) {
		req := reqWithLocal(http.MethodGet, "example.com:443", "https", "10.0.0.9:5555", local)
		if err := p.checkLocalAccess(req); err != nil {
			t.Fatalf("external target wrongly forbidden: %v", err)
		}
	})
}

func TestAccess_NoAuthForbidsInterfaceIP(t *testing.T) {
	p := &Proxy{}
	local := &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080}
	addrs, _ := net.InterfaceAddrs()
	var lanIP net.IP
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			lanIP = ipnet.IP
			break
		}
	}
	if lanIP == nil {
		t.Skip("no non-loopback IPv4 interface")
	}
	target := net.JoinHostPort(lanIP.String(), "22")
	req := reqWithLocal(http.MethodGet, target, "http", "10.0.0.9:5555", local)
	if err := p.checkLocalAccess(req); err == nil {
		t.Fatalf("no-auth target %q should be forbidden", target)
	}
}

func TestAccess_AuthAllowsOtherLocalPort(t *testing.T) {
	p := &Proxy{Auth: func(u, pw string) bool { return true }}
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	req := reqWithLocal(http.MethodGet, "127.0.0.1:6379", "http", "10.0.0.9:5555", local)
	if err := p.checkSelfLoop(req); err != nil {
		t.Fatalf("other local port is not a self-loop: %v", err)
	}
}

func TestAccess_AuthForbidsSelfLoop(t *testing.T) {
	p := &Proxy{Auth: func(u, pw string) bool { return true }}
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	cases := []struct {
		method string
		host   string
	}{
		{http.MethodGet, "127.0.0.1:8080"},
		{http.MethodGet, "localhost:8080"},
		{http.MethodGet, "0.0.0.0:8080"},
		{http.MethodGet, "[::1]:8080"},
		{http.MethodConnect, "127.0.0.1:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.host, func(t *testing.T) {
			req := reqWithLocal(tc.method, tc.host, "http", "10.0.0.9:5555", local)
			if err := p.checkSelfLoop(req); err == nil {
				t.Fatalf("%s %s should be a self-loop", tc.method, tc.host)
			}
		})
	}
}

// ---------- B. isSelfHost ----------

func TestIsSelfHost(t *testing.T) {
	listen := net.ParseIP("127.0.0.1")
	for _, h := range []string{"localhost", "127.0.0.1", "::1", "0.0.0.0", "::", "LOCALHOST"} {
		t.Run("self/"+h, func(t *testing.T) {
			if !isSelfHost(h, listen) {
				t.Fatalf("%q should be self", h)
			}
		})
	}
	for _, h := range []string{"8.8.8.8", "example.com", ""} {
		t.Run("not/"+h, func(t *testing.T) {
			if isSelfHost(h, listen) {
				t.Fatalf("%q should not be self", h)
			}
		})
	}
}

// ---------- C. LinkPosterior ----------

func TestLinkPosterior_RewritesThenAccessCheck(t *testing.T) {
	p := &Proxy{LinkPosterior: true}
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}

	t.Run("local target forbidden without auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/?@url=http://127.0.0.1:6379/", nil)
		req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, local))
		if !p.handleLinkPosterior(req, httptest.NewRecorder()) {
			t.Fatal("handleLinkPosterior should succeed")
		}
		if req.Host != "127.0.0.1:6379" {
			t.Fatalf("host = %q", req.Host)
		}
		if err := p.checkLocalAccess(req); err == nil {
			t.Fatal("local target after rewrite should be forbidden")
		}
	})

	t.Run("external target allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/?@url=https://example.com/a", nil)
		req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, local))
		if !p.handleLinkPosterior(req, httptest.NewRecorder()) {
			t.Fatal("handleLinkPosterior should succeed")
		}
		if req.URL.Scheme != "https" || req.URL.Host != "example.com" || req.URL.Path != "/a" {
			t.Fatalf("url = %s", req.URL)
		}
		if err := p.checkLocalAccess(req); err != nil {
			t.Fatalf("external target wrongly forbidden: %v", err)
		}
	})

	t.Run("bad url", func(t *testing.T) {
		// %5B 解码后是 '['，得到 http://[::1 ，url.Parse 因缺少 ']' 失败。
		// 不能用 ?@url=% ：Query() 会吞掉非法转义，@url 变成空，函数返回 true。
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/?@url=http://%5B::1", nil)
		rr := httptest.NewRecorder()
		if p.handleLinkPosterior(req, rr) {
			t.Fatal("bad url should fail")
		}
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code = %d", rr.Code)
		}
	})
}

// ---------- D. copyData ----------

func TestCopyData(t *testing.T) {
	t.Run("counts bytes", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader(strings.Repeat("a", 10000)))
		var dst strings.Builder
		n, err := copyData(&dst, src, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if n != 10000 || dst.Len() != 10000 {
			t.Fatalf("n=%d dst=%d", n, dst.Len())
		}
	})

	t.Run("flushes http.ResponseWriter", func(t *testing.T) {
		rr := httptest.NewRecorder()
		src := io.NopCloser(strings.NewReader("xyz"))
		if _, err := copyData(rr, src, 8); err != nil {
			t.Fatal(err)
		}
		if rr.Body.String() != "xyz" {
			t.Fatalf("body = %q", rr.Body.String())
		}
	})

	t.Run("default buf size", func(t *testing.T) {
		src := io.NopCloser(strings.NewReader("hi"))
		var dst strings.Builder
		if _, err := copyData(&dst, src, 0); err != nil {
			t.Fatal(err)
		}
		if dst.String() != "hi" {
			t.Fatalf("body = %q", dst.String())
		}
	})
}

// ---------- 可选公网集成（原 baidu / 12306 用例） ----------

func TestIntegration_PublicSites(t *testing.T) {
	if os.Getenv("VPROXY_INTEGRATION") == "" {
		t.Skip("set VPROXY_INTEGRATION=1 to hit public sites")
	}
	hp := newProxyHTTP(&Proxy{
		DataBufioSize: 1024,
		DialContext:   defaultDial.DialContext,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: hp}
	go srv.Serve(ln)
	defer srv.Close()

	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"baidu http", "GET http://www.baidu.com/index.html HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n", 200},
		{"baidu https", "GET https://www.baidu.com/ HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n", 200},
		{"12306 https", "GET https://kyfw.12306.cn/ HTTP/1.1\r\nHost: kyfw.12306.cn\r\nConnection: close\r\n\r\n", 302},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			if _, err := io.WriteString(conn, tc.raw); err != nil {
				t.Fatal(err)
			}
			res, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			io.Copy(io.Discard, res.Body)
			if res.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", res.StatusCode, tc.want)
			}
		})
	}
}
