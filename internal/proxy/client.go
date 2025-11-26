package proxy

import (
	"context"
	"net/http"
)

// ClientProxy 는 서버로부터 받은 요청을 로컬 HTTP 서비스로 전달하는 클라이언트 측 프록시입니다.
type ClientProxy struct {
	HTTPClient *http.Client
}

// StartLoop 는 DTLS 세션에서 protocol.Request 를 읽고 로컬 HTTP 요청을 수행한 뒤
// protocol.Response 를 다시 세션으로 쓰는 루프를 의미합니다.
// 실제 구현은 dtls.Session, protocol.{Request,Response} 를 조합해 작성합니다.
func (p *ClientProxy) StartLoop(ctx context.Context) error {
	// TODO: DTLS 세션 읽기/쓰기 및 로컬 HTTP 호출 구현
	return nil
}
