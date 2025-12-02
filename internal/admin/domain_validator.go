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
		// [nitpick] If the input is a bracketed IPv6 address without a port (e.g., "[::1]"),
		// net.SplitHostPort fails, and the fallback above won't execute due to the ']' check.
		// For robustness, strip brackets if present. Note: normalizeDomain requires a dot,
		// so IP addresses (including IPv6) will be rejected downstream.
		if strings.HasPrefix(d, "[") && strings.HasSuffix(d, "]") {
			d = d[1 : len(d)-1]
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
