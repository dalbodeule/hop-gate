package dtls

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dalbodeule/hop-gate/internal/logging"
)

// DomainValidator 는 (domain, clientAPIKey) 조합이 유효한지 검증하는 인터페이스입니다.
// 실제 구현에서는 ent + PostgreSQL 을 사용해 Domain 테이블을 조회하면 됩니다.
type DomainValidator interface {
	ValidateDomainAPIKey(ctx context.Context, domain, clientAPIKey string) error
}

// ServerHandshakeResult 는 서버 측에서 핸드셰이크가 완료된 후의 정보를 담습니다.
type ServerHandshakeResult struct {
	Domain string
}

// ClientHandshakeResult 는 클라이언트 측에서 핸드셰이크가 완료된 후의 정보를 담습니다.
type ClientHandshakeResult struct {
	Domain  string
	Message string
}

// handshakeRequest 는 클라이언트가 최초 DTLS 연결 후 서버로 보내는 메시지입니다.
// - Domain: 사용할 도메인 (예: api.example.com)
// - ClientAPIKey: 관리 plane 을 통해 발급받은 64자 API Key
type handshakeRequest struct {
	Domain       string `json:"domain"`
	ClientAPIKey string `json:"client_api_key"`
}

// handshakeResponse 는 서버가 핸드셰이크 결과를 클라이언트로 돌려줄 때 사용하는 메시지입니다.
type handshakeResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Domain  string `json:"domain"`
}

// PerformServerHandshake 는 서버 측에서 DTLS 세션이 생성된 직후 호출되어
// 클라이언트가 보낸 (domain, client_api_key)를 검증합니다.
//
// 성공 시:
//   - 서버 로그에 "어떤 도메인이 연결되었는지" 기록
//   - 클라이언트로 OK 응답을 전송
//   - ServerHandshakeResult 에 도메인 정보를 담아 반환
func PerformServerHandshake(
	ctx context.Context,
	sess Session,
	validator DomainValidator,
	logger logging.Logger,
) (*ServerHandshakeResult, error) {
	log := logger.With(logging.Fields{"phase": "dtls_handshake", "side": "server"})

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var req handshakeRequest
	if err := json.NewDecoder(sess).Decode(&req); err != nil {
		log.Error("failed to read handshake request", logging.Fields{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("read handshake request: %w", err)
	}

	req.Domain = stringTrimSpace(req.Domain)
	req.ClientAPIKey = stringTrimSpace(req.ClientAPIKey)

	if req.Domain == "" || req.ClientAPIKey == "" {
		_ = writeHandshakeResponse(sess, handshakeResponse{
			OK:      false,
			Message: "domain and client_api_key are required",
			Domain:  req.Domain,
		})
		return nil, fmt.Errorf("invalid handshake parameters")
	}

	if err := validator.ValidateDomainAPIKey(ctx, req.Domain, req.ClientAPIKey); err != nil {
		log.Warn("domain/api_key validation failed", logging.Fields{
			"domain": req.Domain,
			"error":  err.Error(),
		})
		_ = writeHandshakeResponse(sess, handshakeResponse{
			OK:      false,
			Message: "invalid domain or api key",
			Domain:  req.Domain,
		})
		return nil, fmt.Errorf("handshake validation failed: %w", err)
	}

	// 검증 성공
	log.Info("dtls handshake success", logging.Fields{
		"domain": req.Domain,
	})

	if err := writeHandshakeResponse(sess, handshakeResponse{
		OK:      true,
		Message: "handshake ok",
		Domain:  req.Domain,
	}); err != nil {
		log.Error("failed to write handshake response", logging.Fields{
			"domain": req.Domain,
			"error":  err.Error(),
		})
		return nil, fmt.Errorf("write handshake response: %w", err)
	}

	return &ServerHandshakeResult{
		Domain: req.Domain,
	}, nil
}

// PerformClientHandshake 는 클라이언트 측에서 DTLS 세션이 생성된 직후 호출되어
// 서버로 (domain, client_api_key)를 전송하고 결과를 검증합니다.
//
// localTarget 은 "로컬에서 요청할 서버 주소" (예: 127.0.0.1:8080) 로,
// 핸드셰이크 성공 시 로그에 함께 출력됩니다.
func PerformClientHandshake(
	ctx context.Context,
	sess Session,
	logger logging.Logger,
	domain string,
	clientAPIKey string,
	localTarget string,
) (*ClientHandshakeResult, error) {
	log := logger.With(logging.Fields{"phase": "dtls_handshake", "side": "client"})

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	req := handshakeRequest{
		Domain:       stringTrimSpace(domain),
		ClientAPIKey: stringTrimSpace(clientAPIKey),
	}

	if req.Domain == "" || req.ClientAPIKey == "" {
		return nil, fmt.Errorf("domain and client_api_key are required")
	}

	if err := writeHandshakeRequest(sess, req); err != nil {
		log.Error("failed to write handshake request", logging.Fields{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("write handshake request: %w", err)
	}

	var resp handshakeResponse
	if err := json.NewDecoder(sess).Decode(&resp); err != nil {
		log.Error("failed to read handshake response", logging.Fields{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("read handshake response: %w", err)
	}

	if !resp.OK {
		log.Error("dtls handshake failed", logging.Fields{
			"domain":  req.Domain,
			"message": resp.Message,
		})
		return nil, fmt.Errorf("handshake failed: %s", resp.Message)
	}

	// 성공 로그: 연결 성공 메시지 + 도메인 + 로컬에서 요청할 서버 주소
	log.Info("dtls handshake success", logging.Fields{
		"domain":       resp.Domain,
		"message":      resp.Message,
		"local_target": localTarget,
	})

	return &ClientHandshakeResult{
		Domain:  resp.Domain,
		Message: resp.Message,
	}, nil
}

// writeHandshakeRequest 는 JSON 인코더를 사용해 handshakeRequest 를 세션으로 전송합니다.
func writeHandshakeRequest(sess Session, req handshakeRequest) error {
	enc := json.NewEncoder(sess)
	return enc.Encode(&req)
}

// writeHandshakeResponse 는 JSON 인코더를 사용해 handshakeResponse 를 세션으로 전송합니다.
func writeHandshakeResponse(sess Session, resp handshakeResponse) error {
	enc := json.NewEncoder(sess)
	return enc.Encode(&resp)
}

func stringTrimSpace(s string) string {
	return strings.TrimSpace(s)
}
