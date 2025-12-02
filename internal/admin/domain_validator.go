package admin

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/dalbodeule/hop-gate/ent"
	entdomain "github.com/dalbodeule/hop-gate/ent/domain"
	"github.com/dalbodeule/hop-gate/internal/dtls"
	"github.com/dalbodeule/hop-gate/internal/logging"
)

// entDomainValidator 는 ent.Client 를 사용해 Domain 테이블에서
// (domain, client_api_key) 조합을 검증하는 DomainValidator 구현체입니다.
type entDomainValidator struct {
	logger logging.Logger
	client *ent.Client
}

// NewEntDomainValidator 는 ent 기반 DomainValidator 를 생성합니다.
//   - domain 파라미터는 "host" 또는 "host:port" 형태 모두 허용하며,
//     DB 조회 시에는 host 부분만 사용합니다.
func NewEntDomainValidator(logger logging.Logger, client *ent.Client) dtls.DomainValidator {
	return &entDomainValidator{
		logger: logger.With(logging.Fields{"component": "domain_validator"}),
		client: client,
	}
}

// canonicalDomainForLookup 는 handshake 에서 전달된 domain 문자열을
// DB 조회용 정규 도메인으로 변환합니다.
// - "host:port" 형태인 경우 port 를 제거하고 host 만 사용합니다.
// - 공백 제거 및 소문자 변환 후, normalizeDomain 을 통해 기본 형식을 검증합니다.
func canonicalDomainForLookup(raw string) string {
	d := strings.TrimSpace(raw)
	if d == "" {
		return ""
	}

	// host:port 형태를 우선적으로 처리합니다.
	if h, _, err := net.SplitHostPort(d); err == nil && strings.TrimSpace(h) != "" {
		d = h
	} else {
		// net.SplitHostPort 가 실패했지만 콜론이 포함되어 있는 경우 (예: 잘못된 포맷),
		// IPv6 를 고려하지 않는 단순 환경에서는 마지막 콜론 기준으로 host 부분만 시도해볼 수 있습니다.
		if idx := strings.LastIndex(d, ":"); idx > 0 && !strings.Contains(d, "]") {
			if h := strings.TrimSpace(d[:idx]); h != "" {
				d = h
			}
		}
	}

	// admin/service.go 에 정의된 normalizeDomain 과 동일한 규칙을 적용합니다.
	return normalizeDomain(d)
}

// ValidateDomainAPIKey 는 (domain, client_api_key) 조합을 DB 에서 검증합니다.
func (v *entDomainValidator) ValidateDomainAPIKey(ctx context.Context, domain, clientAPIKey string) error {
	if v.client == nil {
		return fmt.Errorf("domain validator: ent client is nil")
	}

	d := canonicalDomainForLookup(domain)
	key := strings.TrimSpace(clientAPIKey)

	if d == "" || key == "" {
		return fmt.Errorf("domain validator: invalid domain or client_api_key")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	log := v.logger.With(logging.Fields{
		"domain":                d,
		"client_api_key_masked": maskKey(key),
	})

	// Domain 테이블에서 정확히 일치하는 (domain, client_api_key) 를 조회합니다.
	exists, err := v.client.Domain.
		Query().
		Where(
			entdomain.DomainEQ(d),
			entdomain.ClientAPIKeyEQ(key),
		).
		Exist(ctx)
	if err != nil {
		log.Error("failed to query domain/client_api_key from db", logging.Fields{
			"error": err.Error(),
		})
		return fmt.Errorf("domain validator: db query failed: %w", err)
	}

	if !exists {
		log.Warn("no matching domain/client_api_key found", nil)
		return fmt.Errorf("domain validator: domain/api_key not found")
	}

	log.Debug("domain/api_key validation succeeded", nil)
	return nil
}
