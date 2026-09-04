package tunnel

import "context"

// DomainValidator validates the client credentials presented on the control stream.
type DomainValidator interface {
	ValidateDomainAPIKey(ctx context.Context, domain, clientAPIKey string) error
}

// Response is the response returned by a tunnel transport to the public HTTP ingress.
type Response struct {
	RequestID string
	Status    int
	Header    map[string][]string
	Body      []byte
	Error     string
}
