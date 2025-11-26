package proxy

import (
	"context"
	"net/http"

	"golang.org/x/net/http2"
)

// ServerProxy 는 공인 HTTP(S) 엔드포인트에서 들어오는 요청을
// 적절한 클라이언트로 라우팅하는 서버 측 프록시입니다.
type ServerProxy struct {
	Router     Router
	HTTPServer *http.Server
}

// Router 는 도메인/패스 기준으로 어떤 클라이언트/서비스로 보낼지 결정하는 인터페이스입니다.
type Router interface {
	Route(req *http.Request) (clientID string, serviceName string, err error)
}

// NewHTTPServer 는 H1/H2 를 지원하는 기본 HTTP 서버를 생성합니다.
func NewHTTPServer(addr string, handler http.Handler) *http.Server {
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}
	http2.ConfigureServer(srv, &http2.Server{})
	return srv
}

// Start / Shutdown 등은 추후 구현합니다.
func (p *ServerProxy) Start(ctx context.Context) error {
	// TODO: HTTP/HTTPS 리스너 시작 및 DTLS 연동
	return nil
}

func (p *ServerProxy) Shutdown(ctx context.Context) error {
	if p.HTTPServer != nil {
		return p.HTTPServer.Shutdown(ctx)
	}
	return nil
}
