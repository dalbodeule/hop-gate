package proxy

import (
	"bytes"
	"context"
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

// StartLoop 는 DTLS 세션에서 protocol.Envelope 를 읽고, HTTP 요청의 경우 로컬 HTTP 요청을 수행한 뒤
// protocol.Envelope(HTTP 응답 포함)을 다시 세션으로 쓰는 루프를 실행합니다. (ko)
// StartLoop reads protocol.Envelope messages from the DTLS session; for HTTP messages it
// performs local HTTP requests and writes back HTTP responses wrapped in an Envelope. (en)
func (p *ClientProxy) StartLoop(ctx context.Context, sess dtls.Session) error {
	if ctx == nil {
		ctx = context.Background()
	}
	log := p.Logger

	// NOTE: pion/dtls 는 복호화된 애플리케이션 데이터를 호출자가 제공한 버퍼에 채워 넣습니다.
	// 기본 JSON 디코더 버퍼(수백 바이트 수준)만 사용하면 큰 HTTP 바디/Envelope 에서
	// "dtls: buffer too small" 오류가 날 수 있으므로, 여기서는 여유 있는 버퍼(64KiB)를 사용합니다. (ko)
	// NOTE: pion/dtls decrypts application data into the buffer provided by the caller.
	// Using only the default JSON decoder buffer (a few hundred bytes) can trigger
	// "dtls: buffer too small" for large HTTP bodies/envelopes. The default
	// JSON-based WireCodec internally wraps the DTLS session with a 64KiB
	// bufio.Reader, matching this requirement. (en)
	codec := protocol.DefaultCodec

	for {
		select {
		case <-ctx.Done():
			log.Info("client proxy loop stopping due to context cancellation", logging.Fields{
				"reason": ctx.Err().Error(),
			})
			return nil
		default:
		}

		var env protocol.Envelope
		if err := codec.Decode(sess, &env); err != nil {
			if err == io.EOF {
				log.Info("dtls session closed by server", nil)
				return nil
			}
			log.Error("failed to decode protocol envelope", logging.Fields{
				"error": err.Error(),
			})
			return err
		}

		// 현재는 HTTP 타입만 지원하며, 그 외 타입은 에러로 처리합니다.
		if env.Type != protocol.MessageTypeHTTP || env.HTTPRequest == nil {
			log.Error("received unsupported envelope type from server", logging.Fields{
				"type": env.Type,
			})
			return fmt.Errorf("unsupported envelope type %q or missing http_request", env.Type)
		}

		req := env.HTTPRequest

		start := time.Now()
		logReq := log.With(logging.Fields{
			"request_id":   req.RequestID,
			"service":      req.ServiceName,
			"method":       req.Method,
			"url":          req.URL,
			"client_id":    req.ClientID,
			"local_target": p.LocalTarget,
		})
		logReq.Info("received http envelope from server", nil)

		resp := protocol.Response{
			RequestID: req.RequestID,
			Header:    make(map[string][]string),
		}

		// 로컬 HTTP 요청 수행
		if err := p.forwardToLocal(ctx, req, &resp); err != nil {
			resp.Status = http.StatusBadGateway
			resp.Error = err.Error()
			logReq.Error("local http request failed", logging.Fields{
				"error": err.Error(),
			})
		}

		// HTTP 응답을 Envelope 로 감싸서 서버로 전송합니다.
		respEnv := protocol.Envelope{
			Type:         protocol.MessageTypeHTTP,
			HTTPResponse: &resp,
		}

		if err := codec.Encode(sess, &respEnv); err != nil {
			logReq.Error("failed to encode http response envelope", logging.Fields{
				"error": err.Error(),
			})
			return err
		}

		logReq.Info("http response envelope sent to server", logging.Fields{
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

	// DTLS over UDP has an upper bound on packet size (~64KiB). 전체 HTTP 바디를
	// 하나의 Envelope 로 감싸 전송하는 현재 설계에서는, 바디가 너무 크면
	// OS 레벨에서 "message too long" (EMSGSIZE) 가 발생할 수 있습니다. (ko)
	//
	// 이를 피하기 위해, 터널링 가능한 **단일 HTTP 바디** 크기에 상한을 두고,
	// 이를 초과하는 응답은 502 Bad Gateway + HopGate 전용 에러 메시지로 대체합니다. (ko)
	//
	// DTLS over UDP has an upper bound on datagram size (~64KiB). With the current
	// single-envelope design, very large bodies can still trigger "message too long"
	// (EMSGSIZE) at the OS level. To avoid this, we cap the tunneled HTTP body size
	// and replace oversized responses with a 502 Bad Gateway + HopGate-specific
	// error body. (en)
	//
	// Protobuf 기반 터널링에서는 향후 StreamData(4KiB) 단위로 나누어 전송할 예정이지만,
	// 그 전 단계에서도 body 자체를 4KiB( StreamChunkSize )로 하드 리밋하여
	// Proto message body 필드가 지나치게 커지지 않도록 합니다. (ko)
	//
	// Even before full stream tunneling is implemented, we hard-limit the protobuf
	// body field to 4KiB (StreamChunkSize) so that individual messages remain small. (en)
	const maxTunnelBodyBytes = protocol.StreamChunkSize

	limited := &io.LimitedReader{
		R: res.Body,
		N: maxTunnelBodyBytes + 1, // read up to limit+1 to detect overflow
	}
	body, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read http response body: %w", err)
	}
	if len(body) > maxTunnelBodyBytes {
		// 응답 바디가 너무 커서 DTLS/UDP 로 안전하게 전송하기 어렵기 때문에,
		// 원본 바디 대신 HopGate 에러 응답으로 대체합니다. (ko)
		//
		// The response body is too large to be safely tunneled over DTLS/UDP.
		// Replace it with a HopGate error response instead of attempting to
		// send an oversized datagram. (en)
		presp.Status = http.StatusBadGateway
		presp.Header = map[string][]string{
			"Content-Type": {"text/plain; charset=utf-8"},
		}
		presp.Body = []byte("HopGate: response body too large for DTLS tunnel (over max_tunnel_body_bytes)")
		presp.Error = "response body too large for DTLS tunnel"
		return nil
	}

	presp.Body = body

	return nil
}
