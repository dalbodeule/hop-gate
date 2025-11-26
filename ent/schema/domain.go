package schema

import (
	"time"

	"github.com/google/uuid"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Domain 는 클라이언트가 사용할 도메인과 API Key 를 저장하는 엔티티입니다.
// - id: UUID 기본 키
// - domain: FQDN (예: app.example.com)
// - client_api_key: 클라이언트 인증용 랜덤 문자열(64자)
// - memo: 관리자 메모
// - created_at / updated_at: 감사용 타임스탬프
type Domain struct {
	ent.Schema
}

// Fields of the Domain.
func (Domain) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.String("domain").
			NotEmpty().
			Unique().
			Immutable(),
		field.String("client_api_key").
			NotEmpty().
			MaxLen(64),
		field.String("memo").
			Default(""),
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes of the Domain.
func (Domain) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_api_key").Unique(),
	}
}
