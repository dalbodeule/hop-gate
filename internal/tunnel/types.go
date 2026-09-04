package tunnel

import "context"

// DomainValidator validates the client credentials presented on the control stream.
type DomainValidator interface {
	ValidateDomainAPIKey(ctx context.Context, domain, clientAPIKey string) error
}
