package vproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// HTTP 转发测试分三类：
//   - 绝对 URL（http）：本地上游，校验状态码与逐跳头
//   - 查询参数：@skipVerify / @browserVer 不得转发到上游
//   - 畸形请求：URL 为空
//
// 依赖公网的 https 用例见 proxy 集成测试，默认不跑。

func newTestHTTPProxy(dial func(ctx context.Context, network, address string) (net.Conn, error)) *proxyHTTP {
	return newProxyHTTP(&Proxy{
		DataBufioSize: 1024,
		DialContext:   dial,
	})
}

func forwardRaw(t *testing.T, h http.Handler, raw string) *http.Response {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// 分类：绝对形式 HTTP 请求
func TestHTTPProxy_AbsoluteHTTP(t *testing.T) {
	const body = "upstream-ok"
	var gotPath, gotProxyConn, gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotProxyConn = r.Header.Get("Proxy-Connection")
		gotQuery = r.URL.RawQuery
		w.Header().Set("X-From", "upstream")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()

	hp := newTestHTTPProxy(func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, upstream.Listener.Addr().String())
	})

	raw := "GET http://example.test/index.html?@skipVerify=true&n=1 HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Proxy-Connection: Keep-Alive\r\n" +
		"Connection: close\r\n\r\n"
	res := forwardRaw(t, hp, raw)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	got, _ := io.ReadAll(res.Body)
	if string(got) != body {
		t.Fatalf("body = %q", got)
	}
	if gotPath != "/index.html" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotProxyConn != "" {
		t.Fatalf("Proxy-Connection forwarded: %q", gotProxyConn)
	}
	if strings.Contains(gotQuery, "@skipVerify") {
		t.Fatalf("@skipVerify leaked to upstream: %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "n=1") {
		t.Fatalf("business query dropped: %q", gotQuery)
	}
	if res.Header.Get("Connection") != "" {
		t.Fatalf("hop header Connection leaked: %q", res.Header.Get("Connection"))
	}
	if res.Header.Get("X-From") != "upstream" {
		t.Fatalf("X-From = %q", res.Header.Get("X-From"))
	}
}

// 分类：只有 Host、没有 scheme 的请求会被补成 https。
// 这里不断言拨号成功，只断言缺 URL 时不会 panic。
func TestHTTPProxy_NilURL(t *testing.T) {
	hp := newTestHTTPProxy(func(ctx context.Context, network, address string) (net.Conn, error) {
		t.Fatal("should not dial")
		return nil, nil
	})
	req := &http.Request{Method: http.MethodGet, Header: make(http.Header)}
	rr := httptest.NewRecorder()
	hp.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("code = %d body = %s", rr.Code, rr.Body.String())
	}
}

// 分类：头清理（不连上游）
func TestCleanProxyHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/path", nil)
	req.Header.Set("Referer", "https://origin.example/")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Proxy-Authorization", "Basic eA==")
	cleanProxyHeaders(req)
	if req.Header.Get("Proxy-Connection") != "" || req.Header.Get("Proxy-Authorization") != "" {
		t.Fatalf("proxy-* headers left: %v", req.Header)
	}
	if got := req.Header.Get("Referer"); got != "https://origin.example/" {
		t.Fatalf("Referer = %q, must not be overwritten", got)
	}
}

// 分类：H2 池 key 必须把影响 TLS 的参数算进去
func TestH2PoolKey(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		addr string
	}{
		{"plain", context.Background(), "example.com:443"},
		{"skip", context.WithValue(context.Background(), ctxKeySkipVerify, true), "example.com:443"},
		{"ver", context.WithValue(context.Background(), ctxKeyBrowserVer, "120"), "example.com:443"},
		{"other-host", context.Background(), "other.com:443"},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		k := h2PoolKey(tc.ctx, tc.addr)
		if prev, ok := seen[k]; ok {
			t.Fatalf("key collision between %s and %s: %s", prev, tc.name, k)
		}
		seen[k] = tc.name
	}
}

// 分类：可重放 Body 在失败后能恢复；不可重放则 reset 为 no-op
func TestResetRequestBody(t *testing.T) {
	t.Run("replayable", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("abc"))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("abc")), nil
		}
		// 模拟 H2 RoundTrip 已读走 Body
		_, _ = io.Copy(io.Discard, req.Body)
		if err := resetRequestBody(req); err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(req.Body)
		if string(b) != "abc" {
			t.Fatalf("body = %q", b)
		}
	})
	t.Run("nobody", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		if err := resetRequestBody(req); err != nil {
			t.Fatal(err)
		}
	})
}

// 读请求辅助，避免测试里散落 bytes.Buffer
func TestReadProxyRequestShape(t *testing.T) {
	raw := "GET http://www.example.com/index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewBufferString(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Host != "www.example.com" || req.URL.Path != "/index.html" {
		t.Fatalf("url = %s", req.URL)
	}
}
