package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/dalbodeule/hop-gate/ent"
	entdomain "github.com/dalbodeule/hop-gate/ent/domain"
	"github.com/dalbodeule/hop-gate/internal/logging"
)

// DomainService 는 도메인 등록/해제 및 조회를 담당하는 비즈니스 로직 인터페이스입니다.
// 실제 구현에서는 ent.Client(PostgreSQL)를 주입받아 동작하게 됩니다.
type DomainService interface {
	// RegisterDomain 은 새로운 도메인을 등록하고, 해당 도메인을 사용할 클라이언트 API Key(랜덤 64자)를 생성해 반환합니다.
	RegisterDomain(ctx context.Context, domain, memo string) (clientAPIKey string, err error)

	// UnregisterDomain 은 도메인과 클라이언트 API Key를 함께 받아 등록을 해제합니다.
	UnregisterDomain(ctx context.Context, domain, clientAPIKey string) error

	// IsDomainRegistered 는 주어진 도메인이 이미 등록되어 있는지 여부를 반환합니다.
	IsDomainRegistered(ctx context.Context, domain string) (bool, error)

	// GetDomain 은 주어진 도메인에 대한 전체 엔티티 정보를 반환합니다.
	// 존재하지 않으면 ErrDomainNotFound 를 반환합니다.
	GetDomain(ctx context.Context, domain string) (*ent.Domain, error)
}

// DomainServiceImpl 는 ent.Client 를 사용해 DomainService 를 구현한 구조체입니다.
type DomainServiceImpl struct {
	logger logging.Logger
	client *ent.Client
}

// NewDomainService 는 기본 DomainService 구현체를 생성합니다.
func NewDomainService(logger logging.Logger, client *ent.Client) DomainService {
	return &DomainServiceImpl{
		logger: logger.With(logging.Fields{"component": "domain_service"}),
		client: client,
	}
}

// RegisterDomain 은 새 도메인을 등록하고, 랜덤 64자 Client API Key 를 생성해 반환합니다.
func (s *DomainServiceImpl) RegisterDomain(ctx context.Context, domain, memo string) (string, error) {
	d := normalizeDomain(domain)
	if d == "" {
		return "", ErrInvalidDomain
	}

	if ctx == nil {
		ctx = context.Background()
	}

	apiKey, err := generateClientAPIKey(64)
	if err != nil {
		return "", fmt.Errorf("generate client api key: %w", err)
	}

	// ent schema 에서 memo 는 빈 문자열 허용
	if memo == "" {
		memo = ""
	}

	_, err = s.client.Domain.Create().
		SetDomain(d).
		SetClientAPIKey(apiKey).
		SetMemo(memo).
		Save(ctx)
	if err != nil {
		s.logger.Error("failed to register domain", logging.Fields{
			"domain": d,
			"error":  err.Error(),
		})
		return "", fmt.Errorf("register domain: %w", err)
	}

	s.logger.Info("domain registered", logging.Fields{
		"domain":                d,
		"client_api_key_masked": maskKey(apiKey),
	})

	return apiKey, nil
}

// UnregisterDomain 은 (domain, client_api_key) 조합이 일치하는 레코드를 삭제합니다.
func (s *DomainServiceImpl) UnregisterDomain(ctx context.Context, domain, clientAPIKey string) error {
	d := normalizeDomain(domain)
	if d == "" {
		return ErrInvalidDomain
	}
	key := strings.TrimSpace(clientAPIKey)
	if key == "" {
		return ErrInvalidClientAPIKey
	}

	if ctx == nil {
		ctx = context.Background()
	}

	del := s.client.Domain.Delete().
		Where(
			entdomain.DomainEQ(d),
			entdomain.ClientAPIKeyEQ(key),
		)

	n, err := del.Exec(ctx)
	if err != nil {
		s.logger.Error("failed to unregister domain", logging.Fields{
			"domain": d,
			"error":  err.Error(),
		})
		return fmt.Errorf("unregister domain: %w", err)
	}
	if n == 0 {
		return ErrDomainNotFound
	}

	s.logger.Info("domain unregistered", logging.Fields{
		"domain":                d,
		"client_api_key_masked": maskKey(key),
	})

	return nil
}

// IsDomainRegistered 는 주어진 도메인이 이미 등록되어 있는지 여부를 반환합니다.
func (s *DomainServiceImpl) IsDomainRegistered(ctx context.Context, domain string) (bool, error) {
	d := normalizeDomain(domain)
	if d == "" {
		return false, ErrInvalidDomain
	}

	if ctx == nil {
		ctx = context.Background()
	}

	cnt, err := s.client.Domain.Query().
		Where(entdomain.DomainEQ(d)).
		Count(ctx)
	if err != nil {
		s.logger.Error("failed to check domain existence", logging.Fields{
			"domain": d,
			"error":  err.Error(),
		})
		return false, fmt.Errorf("check domain existence: %w", err)
	}
	return cnt > 0, nil
}

// GetDomain 은 주어진 도메인에 대한 전체 엔티티 정보를 반환합니다.
// 존재하지 않으면 ErrDomainNotFound 를 반환합니다.
func (s *DomainServiceImpl) GetDomain(ctx context.Context, domain string) (*ent.Domain, error) {
	d := normalizeDomain(domain)
	if d == "" {
		return nil, ErrInvalidDomain
	}

	if ctx == nil {
		ctx = context.Background()
	}

	row, err := s.client.Domain.Query().
		Where(entdomain.DomainEQ(d)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrDomainNotFound
		}
		s.logger.Error("failed to get domain", logging.Fields{
			"domain": d,
			"error":  err.Error(),
		})
		return nil, fmt.Errorf("get domain: %w", err)
	}
	return row, nil
}

// generateClientAPIKey 는 랜덤 바이트를 생성하여 hex 문자열로 인코딩합니다.
func generateClientAPIKey(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid key length: %d", length)
	}

	// hex 인코딩 결과 길이가 length 이상이 되도록 필요한 바이트 수 계산
	byteLen := (length + 1) / 2
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := hex.EncodeToString(b)
	if len(s) > length {
		s = s[:length]
	}
	return s, nil
}

// normalizeDomain 은 도메인 문자열을 소문자/공백 트리밍하고, 간단한 형식을 검증합니다.
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return ""
	}
	// 매우 단순한 FQDN 검증: 점(.) 포함 및 공백 없음만 확인.
	if !strings.Contains(d, ".") {
		return ""
	}
	if strings.ContainsAny(d, " \t\r\n") {
		return ""
	}
	return d
}

// maskKey 는 로그 등에 사용할 수 있도록 API 키를 마스킹합니다.
func maskKey(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 8 {
		if key == "" {
			return ""
		}
		return "***"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// 에러 타입 정의 (추후 DomainValidator 구현에서도 재사용 가능).
var (
	// ErrInvalidDomain 은 도메인 문자열이 비어있거나 형식이 잘못된 경우를 나타냅니다.
	ErrInvalidDomain = errors.New("invalid domain")

	// ErrInvalidClientAPIKey 는 client_api_key 가 비어있는 경우를 나타냅니다.
	ErrInvalidClientAPIKey = errors.New("invalid client api key")

	// ErrDomainNotFound 는 (domain, client_api_key) 조합에 해당하는 레코드가 없는 경우를 나타냅니다.
	ErrDomainNotFound = errors.New("domain not found")
)
