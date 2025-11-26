package acme

import "crypto/tls"

// Manager 는 ACME 기반 인증서 관리를 추상화합니다.
type Manager interface {
	// TLSConfig 는 HTTPS 및 DTLS 서버에 주입할 tls.Config 를 반환합니다.
	TLSConfig() *tls.Config
}

// NewDummyManager 는 초기 개발 단계를 위한 더미 구현입니다.
// 실제 ACME 연동 전까지 self-signed 등의 임시 인증서를 제공하도록 확장할 수 있습니다.
func NewDummyManager() Manager {
	return &dummyManager{}
}

type dummyManager struct{}

func (d *dummyManager) TLSConfig() *tls.Config {
	// TODO: 실제 인증서 로딩/ACME 연동 구현
	return &tls.Config{}
}
