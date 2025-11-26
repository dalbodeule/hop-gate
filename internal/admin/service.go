package admin

import "context"

// DomainService 는 도메인 등록/해제를 담당하는 비즈니스 로직 인터페이스입니다.
// 실제 구현에서는 ent.Client(PostgreSQL)를 주입받아 동작하게 됩니다.
type DomainService interface {
	// RegisterDomain 은 새로운 도메인을 등록하고, 해당 도메인을 사용할 클라이언트 API Key(랜덤 64자)를 생성해 반환합니다.
	RegisterDomain(ctx context.Context, domain, memo string) (clientAPIKey string, err error)

	// UnregisterDomain 은 도메인과 클라이언트 API Key를 함께 받아 등록을 해제합니다.
	UnregisterDomain(ctx context.Context, domain, clientAPIKey string) error
}
