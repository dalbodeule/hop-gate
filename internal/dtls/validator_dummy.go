package dtls

import (
	"context"

	"github.com/dalbodeule/hop-gate/internal/logging"
)

// DomainValidator 는 handshake.go 에 정의된 인터페이스를 재노출합니다.
// (동일 패키지이므로 별도 선언 없이 사용하지만, 여기에 더미 구현을 둡니다.)

// DummyDomainValidator 는 임시 개발용으로 모든 (domain, api_key) 조합을 허용하는 Validator 입니다.
// 실제 운영 환경에서는 ent + PostgreSQL 기반의 구현으로 교체해야 합니다.
type DummyDomainValidator struct {
	Logger logging.Logger
}

func (d DummyDomainValidator) ValidateDomainAPIKey(ctx context.Context, domain, clientAPIKey string) error {
	if d.Logger != nil {
		d.Logger.Debug("dummy domain validator used (ALWAYS ALLOW)", logging.Fields{
			"domain":                domain,
			"client_api_key_masked": maskKey(clientAPIKey),
		})
	}
	return nil
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "..." + key[len(key)-4:]
}
