package vproxy

import (
	"net/http"
    "io"
    "strings"
)

var hopHeaders = []string{
	//"Connection",
	"Proxy-Connection",
	//"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	//"Upgrade",
}

type proxyHTTP struct{
    *Proxy

}

func (T *proxyHTTP) ServeHTTP(rw http.ResponseWriter, req *http.Request){
	outreq := new(http.Request)
	*outreq = *req

    //客户端关闭后，同时代理服务器的请求也取消。
	if closeNotifier, ok := rw.(http.CloseNotifier); ok {
		if requestCancel, ok := T.Proxy.tr.(requestCanceler); ok {
			reqDone := make(chan struct{})
			defer close(reqDone)

			clientGone := closeNotifier.CloseNotify()

			outreq.Body = struct{
				io.Reader
				io.Closer
			}{
				Reader: &runOnFirstRead{
					Reader: outreq.Body,
					fn: func() {
						go func() {
							select {
							case <-clientGone:
								requestCancel.CancelRequest(outreq)
							case <-reqDone:
							}
						}()
					},
				},
				Closer: outreq.Body,
			}
		}
	}

    //处理请求
    completionURL(outreq)
    outreq.RequestURI = ""
	outreq.Header = make(http.Header)
    filterHeaders(req.Header)
	copyHeaders(outreq.Header, req.Header)
	
	resp, err := T.Proxy.tr.RoundTrip(outreq)
    if resp != nil {
        defer resp.Body.Close()
    }
	if err != nil {
        T.Proxy.logf(Error, err.Error())
        //502 服务器作为网关或者代理时，为了完成请求访问下一个服务器，但该服务器返回了非法的应答。
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}

    T.Proxy.logf(Response, "响应：\r\n%v", resp)

	wh := rw.Header()
    clearHeaders(wh)
    filterHeaders(resp.Header)
	copyHeaders(wh, resp.Header)

	if len(resp.Trailer) > 0 {
		var trailerKeys []string
		for k := range resp.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

    rw.WriteHeader(resp.StatusCode)

	if len(resp.Trailer) > 0 {
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

    var bufSize int = defaultDataBufioSize
    if T.Proxy.DataBufioSize != 0 {
        bufSize = T.Proxy.DataBufioSize
    }

    copyDate(rw, resp.Body, bufSize)
}


type requestCanceler interface {
	CancelRequest(*http.Request)
}

func completionURL(req *http.Request){
    //有两种方式：
    //GET / HTTP/1.1
    //Host:www.google.com
    //
    //GET http://www.google.com/ HTTP/1.1
    //Host:www.google.com
    //
    if req.URL.Host == ""{
        req.URL.Host = req.Host
    }
    if req.URL.Scheme == "" {
        if req.TLS != nil {
            req.URL.Scheme="https"
        }else{
            req.URL.Scheme="http"
        }
    }
}

func clearHeaders(headers http.Header) {
	for key, _ := range headers {
		headers.Del(key)
	}
}
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
func filterHeaders(h http.Header) {
	for _, hh := range hopHeaders {
		h.Del(hh)
	}
}

type runOnFirstRead struct {
	io.Reader

	fn func()
}

func (c *runOnFirstRead) Read(bs []byte) (int, error) {
	if c.fn != nil {
		c.fn()
		c.fn = nil
	}
	if c.Reader == nil {
		return 0, io.EOF
	}
	return c.Reader.Read(bs)
}
