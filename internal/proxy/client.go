package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/dalbodeule/hop-gate/internal/dtls"
	"github.com/dalbodeule/hop-gate/internal/logging"
	"github.com/dalbodeule/hop-gate/internal/protocol"
)

// ClientProxy 는 서버로부터 받은 요청을 로컬 HTTP 서비스로 전달하는 클라이언트 측 프록시입니다. (ko)
// ClientProxy forwards requests from the server to local HTTP services. (en)
type ClientProxy struct {
	HTTPClient  *http.Client
	Logger      logging.Logger
	LocalTarget string // e.g. "127.0.0.1:8080"
}

// NewClientProxy 는 기본 HTTP 클라이언트 및 로거를 사용해 ClientProxy 를 생성합니다. (ko)
// NewClientProxy creates a ClientProxy with a default HTTP client and logger. (en)
func NewClientProxy(logger logging.Logger, localTarget string) *ClientProxy {
	if logger == nil {
		logger = logging.NewStdJSONLogger("client_proxy")
	}
	return &ClientProxy{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		Logger:      logger.With(logging.Fields{"component": "client_proxy"}),
		LocalTarget: localTarget,
	}
}

// StartLoop 는 DTLS 세션에서 protocol.Request 를 읽고 로컬 HTTP 요청을 수행한 뒤
// protocol.Response 를 다시 세션으로 쓰는 루프를 실행합니다. (ko)
// StartLoop reads protocol.Request messages from the DTLS session, performs local HTTP
// requests, and writes back protocol.Response objects. (en)
func (p *ClientProxy) StartLoop(ctx context.Context, sess dtls.Session) error {
	if ctx == nil {
		ctx = context.Background()
	}
	log := p.Logger

	dec := json.NewDecoder(sess)
	enc := json.NewEncoder(sess)

	for {
		select {
		case <-ctx.Done():
			log.Info("client proxy loop stopping due to context cancellation", logging.Fields{
				"reason": ctx.Err().Error(),
			})
			return nil
		default:
		}

		var req protocol.Request
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				log.Info("dtls session closed by server", nil)
				return nil
			}
			log.Error("failed to decode protocol request", logging.Fields{
				"error": err.Error(),
			})
			return err
		}

		start := time.Now()
		logReq := log.With(logging.Fields{
			"request_id":   req.RequestID,
			"service":      req.ServiceName,
			"method":       req.Method,
			"url":          req.URL,
			"client_id":    req.ClientID,
			"local_target": p.LocalTarget,
		})
		logReq.Info("received protocol request from server", nil)

		resp := protocol.Response{
			RequestID: req.RequestID,
			Header:    make(map[string][]string),
		}

		// 로컬 HTTP 요청 수행
		if err := p.forwardToLocal(ctx, &req, &resp); err != nil {
			resp.Status = http.StatusBadGateway
			resp.Error = err.Error()
			logReq.Error("local http request failed", logging.Fields{
				"error": err.Error(),
			})
		}

		if err := enc.Encode(&resp); err != nil {
			logReq.Error("failed to encode protocol response", logging.Fields{
				"error": err.Error(),
			})
			return err
		}

		logReq.Info("protocol response sent to server", logging.Fields{
			"status":     resp.Status,
			"elapsed_ms": time.Since(start).Milliseconds(),
			"error":      resp.Error,
		})
	}
}

// forwardToLocal 는 protocol.Request 를 로컬 HTTP 요청으로 변환하고 protocol.Response 를 채웁니다. (ko)
// forwardToLocal converts a protocol.Request into a local HTTP request and fills protocol.Response. (en)
func (p *ClientProxy) forwardToLocal(ctx context.Context, preq *protocol.Request, presp *protocol.Response) error {
	if p.LocalTarget == "" {
		return fmt.Errorf("local target is empty")
	}

	// 요청 URL을 local target 기준으로 재구성
	u, err := url.Parse(preq.URL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	u.Scheme = "http"
	u.Host = p.LocalTarget

	req, err := http.NewRequestWithContext(ctx, preq.Method, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create http request: %w", err)
	}
	// Body 설정 (원본 바이트를 그대로 사용)
	if len(preq.Body) > 0 {
		buf := bytes.NewReader(preq.Body)
		req.Body = io.NopCloser(buf)
		req.ContentLength = int64(len(preq.Body))
	}
	// 헤더 복사
	for k, vs := range preq.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	res, err := p.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform http request: %w", err)
	}
	defer res.Body.Close()

	presp.Status = res.StatusCode
	for k, vs := range res.Header {
		presp.Header[k] = append([]string(nil), vs...)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read http response body: %w", err)
	}
	presp.Body = body

	return nil
}
