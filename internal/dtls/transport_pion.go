package dtls

import (
	"crypto/tls"
	"fmt"
	"time"
)

// PionServerConfig 는 DTLS 서버 리스너 구성을 정의하는 기존 구조체를 그대로 유지합니다. (ko)
// PionServerConfig keeps the old DTLS server listener configuration shape for compatibility. (en)
type PionServerConfig struct {
	Addr      string
	TLSConfig *tls.Config
}

// PionClientConfig 는 DTLS 클라이언트 구성을 정의하는 기존 구조체를 그대로 유지합니다. (ko)
// PionClientConfig keeps the old DTLS client configuration shape for compatibility. (en)
type PionClientConfig struct {
	Addr      string
	TLSConfig *tls.Config
	Timeout   time.Duration
}

// disabledServer 는 DTLS 전송이 비활성화되었음을 나타내는 더미 구현입니다. (ko)
// disabledServer is a dummy Server implementation indicating that DTLS transport is disabled. (en)
type disabledServer struct{}

func (s *disabledServer) Accept() (Session, error) {
	return nil, fmt.Errorf("dtls transport is disabled; use gRPC tunnel instead")
}

func (s *disabledServer) Close() error {
	return nil
}

// disabledClient 는 DTLS 전송이 비활성화되었음을 나타내는 더미 구현입니다. (ko)
// disabledClient is a dummy Client implementation indicating that DTLS transport is disabled. (en)
type disabledClient struct{}

func (c *disabledClient) Connect() (Session, error) {
	return nil, fmt.Errorf("dtls transport is disabled; use gRPC tunnel instead")
}

func (c *disabledClient) Close() error {
	return nil
}

// NewPionServer 는 더 이상 실제 DTLS 서버를 생성하지 않고, 항상 에러를 반환합니다. (ko)
// NewPionServer no longer creates a real DTLS server and always returns an error. (en)
func NewPionServer(cfg PionServerConfig) (Server, error) {
	return nil, fmt.Errorf("dtls transport is disabled; NewPionServer is no longer supported")
}

// NewPionClient 는 더 이상 실제 DTLS 클라이언트를 생성하지 않고, disabledClient 를 반환합니다. (ko)
// NewPionClient no longer creates a real DTLS client and instead returns a disabledClient. (en)
func NewPionClient(cfg PionClientConfig) Client {
	return &disabledClient{}
}
