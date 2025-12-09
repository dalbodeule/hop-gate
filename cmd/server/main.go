package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	stdfs "io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dalbodeule/hop-gate/internal/acme"
	"github.com/dalbodeule/hop-gate/internal/admin"
	"github.com/dalbodeule/hop-gate/internal/config"
	"github.com/dalbodeule/hop-gate/internal/dtls"
	"github.com/dalbodeule/hop-gate/internal/errorpages"
	"github.com/dalbodeule/hop-gate/internal/logging"
	"github.com/dalbodeule/hop-gate/internal/observability"
	"github.com/dalbodeule/hop-gate/internal/protocol"
	"github.com/dalbodeule/hop-gate/internal/store"
)

// version 은 빌드 시 -ldflags "-X main.version=xxxxxxx" 로 덮어쓰이는 필드입니다.
// 기본값 "dev" 는 로컬 개발용입니다.
var version = "dev"

type dtlsSessionWrapper struct {
	sess           dtls.Session
	bufferedReader *bufio.Reader
	mu             sync.Mutex
	nextStreamID   uint64
}

func getEnvOrPanic(logger logging.Logger, key string) string {
	value, exists := os.LookupEnv(key)
	if !exists || strings.TrimSpace(value) == "" {
		logger.Error("missing required environment variable", logging.Fields{
			"env": key,
		})
		os.Exit(1)
	}
	return value
}

// canonicalizeDomainForDNS 는 DTLS 핸드셰이크에서 전달된 도메인 문자열을
// DNS 조회 및 DB 조회에 사용할 수 있는 정규화된 호스트명으로 변환합니다. (ko)
// canonicalizeDomainForDNS normalizes the domain string from the DTLS handshake
// into a host name suitable for DNS and DB lookups. (en)
func canonicalizeDomainForDNS(raw string) string {
	d := strings.TrimSpace(raw)
	if d == "" {
		return ""
	}
	// "host:port" 형태가 들어온 경우 포트를 제거합니다. (ko)
	// Strip port if the value is in "host:port" form. (en)
	if h, _, err := net.SplitHostPort(d); err == nil && strings.TrimSpace(h) != "" {
		d = h
	}
	return strings.ToLower(d)
}

// domainGateValidator 는 DTLS 핸드셰이크 시 도메인이 EXPECT_IPS(HOP_ACME_EXPECT_IPS)에
// 설정된 IP(IPv4/IPv6)로 해석되는지 검사한 뒤, 내부 DomainValidator 로 위임합니다. (ko)
// domainGateValidator first checks that the domain resolves to one of the
// expected IPs (from HOP_ACME_EXPECT_IPS), then delegates to the inner
// DomainValidator for (domain, client_api_key) validation. (en)
type domainGateValidator struct {
	expectedIPs []net.IP
	inner       dtls.DomainValidator
	logger      logging.Logger
}

func (v *domainGateValidator) ValidateDomainAPIKey(ctx context.Context, domain, clientAPIKey string) error {
	d := canonicalizeDomainForDNS(domain)
	if d == "" {
		return fmt.Errorf("empty domain is not allowed for dtls handshake")
	}

	// EXPECT_IPS(HOP_ACME_EXPECT_IPS)가 설정된 경우, 도메인이 해당 IP(IPv4/IPv6)들로
	// 해석되는지 DNS(A/AAAA) 조회를 통해 검증합니다. (ko)
	// If EXPECT_IPS (HOP_ACME_EXPECT_IPS) is configured, ensure that the domain
	// resolves (via A/AAAA) to at least one of the expected IPs. (en)
	if len(v.expectedIPs) > 0 {
		resolver := net.DefaultResolver
		if ctx == nil {
			ctx = context.Background()
		}
		ips, err := resolver.LookupIP(ctx, "ip", d)
		if err != nil {
			if v.logger != nil {
				v.logger.Warn("dtls handshake dns resolution failed", logging.Fields{
					"domain": d,
					"error":  err.Error(),
				})
			}
			return fmt.Errorf("dns resolution failed for %s: %w", d, err)
		}

		match := false
		for _, ip := range ips {
			for _, expected := range v.expectedIPs {
				if ip.Equal(expected) {
					match = true
					break
				}
			}
			if match {
				break
			}
		}

		if !match {
			if v.logger != nil {
				v.logger.Warn("dtls handshake rejected due to unexpected resolved IPs", logging.Fields{
					"domain":       d,
					"resolved_ips": ips,
					"expected_ips": v.expectedIPs,
				})
			}
			return fmt.Errorf("domain %s does not resolve to any expected IPs", d)
		}
	}

	if v.inner != nil {
		return v.inner.ValidateDomainAPIKey(ctx, d, clientAPIKey)
	}
	return nil
}

// parseExpectedIPsFromEnv 는 HOP_ACME_EXPECT_IPS 와 같이 콤마로 구분된 IP 목록
// 환경변수를 파싱해 net.IP 슬라이스로 변환합니다. IPv4/IPv6 모두 지원합니다. (ko)
// parseExpectedIPsFromEnv parses a comma-separated list of IPs from env (e.g. HOP_ACME_EXPECT_IPS)
// into a slice of net.IP, supporting both IPv4 and IPv6 literals. (en)
func parseExpectedIPsFromEnv(logger logging.Logger, envKey string) []net.IP {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var result []net.IP
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			if logger != nil {
				logger.Warn("invalid ip in env, skipping", logging.Fields{
					"env":   envKey,
					"value": p,
				})
			}
			continue
		}
		result = append(result, ip)
	}
	if logger != nil {
		logger.Info("loaded expected handshake ips from env", logging.Fields{
			"env": envKey,
			"ips": result,
		})
	}
	return result
}

// ForwardHTTP 는 HTTP 요청을 DTLS 세션 위의 StreamOpen/StreamData/StreamClose 프레임으로 전송하고,
// 역방향 스트림 응답을 수신해 protocol.Response 로 반환합니다. (ko)
// ForwardHTTP forwards an HTTP request over the DTLS session using StreamOpen/StreamData/StreamClose
// frames and reconstructs the reverse stream into a protocol.Response. (en)
func (w *dtlsSessionWrapper) ForwardHTTP(ctx context.Context, logger logging.Logger, req *http.Request, serviceName string) (*protocol.Response, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}

	codec := protocol.DefaultCodec

	// 세션 내에서 고유한 StreamID 를 생성합니다. (ko)
	// Generate a unique StreamID for this HTTP request within the DTLS session. (en)
	streamID := w.nextHTTPStreamID()

	log := logger.With(logging.Fields{
		"component":  "http_to_dtls",
		"request_id": string(streamID),
		"method":     req.Method,
		"url":        req.URL.String(),
	})

	log.Info("forwarding http request over dtls (stream mode)", logging.Fields{
		"host":   req.Host,
		"scheme": req.URL.Scheme,
	})

	// 요청 헤더를 복사하고 pseudo-header 로 HTTP 메타데이터를 추가합니다. (ko)
	// Copy request headers and attach HTTP metadata as pseudo-headers. (en)
	hdr := make(map[string][]string, len(req.Header)+3)
	for k, vs := range req.Header {
		hdr[k] = append([]string(nil), vs...)
	}
	hdr[protocol.HeaderKeyMethod] = []string{req.Method}
	if req.URL != nil {
		hdr[protocol.HeaderKeyURL] = []string{req.URL.String()}
	}
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host != "" {
		hdr[protocol.HeaderKeyHost] = []string{host}
	}

	// StreamOpen 전송: 어떤 서비스로 라우팅해야 하는지와 초기 헤더를 전달합니다. (ko)
	// Send StreamOpen to indicate which service to route to and initial headers. (en)
	openEnv := &protocol.Envelope{
		Type: protocol.MessageTypeStreamOpen,
		StreamOpen: &protocol.StreamOpen{
			ID:         streamID,
			Service:    serviceName,
			TargetAddr: "",
			Header:     hdr,
		},
	}
	if err := codec.Encode(w.sess, openEnv); err != nil {
		log.Error("failed to encode stream_open envelope", logging.Fields{
			"error": err.Error(),
		})
		return nil, err
	}

	// 요청 바디를 4KiB(StreamChunkSize) 단위로 잘라 StreamData 프레임으로 전송합니다. (ko)
	// Chunk the request body into 4KiB (StreamChunkSize) StreamData frames. (en)
	var seq uint64
	if req.Body != nil {
		buf := make([]byte, protocol.StreamChunkSize)
		for {
			n, err := req.Body.Read(buf)
			if n > 0 {
				dataCopy := append([]byte(nil), buf[:n]...)
				dataEnv := &protocol.Envelope{
					Type: protocol.MessageTypeStreamData,
					StreamData: &protocol.StreamData{
						ID:   streamID,
						Seq:  seq,
						Data: dataCopy,
					},
				}
				if err2 := codec.Encode(w.sess, dataEnv); err2 != nil {
					log.Error("failed to encode stream_data envelope", logging.Fields{
						"error": err2.Error(),
					})
					return nil, err2
				}
				seq++
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("read http request body for streaming: %w", err)
			}
		}
	}

	// 바디 종료를 알리는 StreamClose 를 전송합니다. (ko)
	// Send StreamClose to mark the end of the request body. (en)
	closeReqEnv := &protocol.Envelope{
		Type: protocol.MessageTypeStreamClose,
		StreamClose: &protocol.StreamClose{
			ID:    streamID,
			Error: "",
		},
	}
	if err := codec.Encode(w.sess, closeReqEnv); err != nil {
		log.Error("failed to encode request stream_close envelope", logging.Fields{
			"error": err.Error(),
		})
		return nil, err
	}

	// 클라이언트로부터 역방향 스트림 응답을 수신합니다. (ko)
	// Receive reverse stream response (StreamOpen + StreamData* + StreamClose). (en)
	var (
		resp       protocol.Response
		bodyBuf    bytes.Buffer
		gotOpen    bool
		statusCode = http.StatusOK
	)

	resp.RequestID = string(streamID)
	resp.Header = make(map[string][]string)

	for {
		var env protocol.Envelope
		if err := codec.Decode(w.bufferedReader, &env); err != nil {
			log.Error("failed to decode stream response envelope", logging.Fields{
				"error": err.Error(),
			})
			return nil, err
		}

		switch env.Type {
		case protocol.MessageTypeStreamOpen:
			so := env.StreamOpen
			if so == nil {
				return nil, fmt.Errorf("stream_open response payload is nil")
			}
			if so.ID != streamID {
				return nil, fmt.Errorf("unexpected stream_open for id %q (expected %q)", so.ID, streamID)
			}
			// 상태 코드 및 헤더 복원 (pseudo-header 제거). (ko)
			// Restore status code and headers (strip pseudo-headers). (en)
			statusStr := firstHeaderValue(so.Header, protocol.HeaderKeyStatus, strconv.Itoa(http.StatusOK))
			if sc, err := strconv.Atoi(statusStr); err == nil && sc > 0 {
				statusCode = sc
			}
			for k, vs := range so.Header {
				if k == protocol.HeaderKeyMethod ||
					k == protocol.HeaderKeyURL ||
					k == protocol.HeaderKeyHost ||
					k == protocol.HeaderKeyStatus {
					continue
				}
				resp.Header[k] = append([]string(nil), vs...)
			}
			gotOpen = true

		case protocol.MessageTypeStreamData:
			sd := env.StreamData
			if sd == nil {
				return nil, fmt.Errorf("stream_data response payload is nil")
			}
			if sd.ID != streamID {
				return nil, fmt.Errorf("unexpected stream_data for id %q (expected %q)", sd.ID, streamID)
			}
			if len(sd.Data) > 0 {
				if _, err := bodyBuf.Write(sd.Data); err != nil {
					return nil, fmt.Errorf("buffer stream_data response: %w", err)
				}
			}

		case protocol.MessageTypeStreamClose:
			sc := env.StreamClose
			if sc == nil {
				return nil, fmt.Errorf("stream_close response payload is nil")
			}
			if sc.ID != streamID {
				return nil, fmt.Errorf("unexpected stream_close for id %q (expected %q)", sc.ID, streamID)
			}
			// 스트림 종료: 지금까지 수신한 헤더/바디로 protocol.Response 를 완성합니다. (ko)
			// Stream finished: complete protocol.Response using collected headers/body. (en)
			resp.Status = statusCode
			resp.Body = bodyBuf.Bytes()
			resp.Error = sc.Error

			log.Info("received stream http response over dtls", logging.Fields{
				"status": resp.Status,
				"error":  resp.Error,
			})
			if !gotOpen {
				return nil, fmt.Errorf("received stream_close without prior stream_open for stream %q", streamID)
			}
			return &resp, nil

		default:
			return nil, fmt.Errorf("unexpected envelope type %q in stream response", env.Type)
		}
	}
}

// nextHTTPStreamID 는 DTLS 세션 내 HTTP 요청에 사용할 고유 StreamID 를 생성합니다. (ko)
// nextHTTPStreamID generates a unique StreamID for HTTP requests on this DTLS session. (en)
func (w *dtlsSessionWrapper) nextHTTPStreamID() protocol.StreamID {
	id := w.nextStreamID
	w.nextStreamID++
	return protocol.StreamID(fmt.Sprintf("http-%d", id))
}

// firstHeaderValue 는 map[string][]string 형태의 헤더에서 첫 번째 값을 반환하고,
// 값이 없으면 기본값을 반환합니다. (ko)
// firstHeaderValue returns the first value for a header key in map[string][]string,
// or the provided default if the key is missing or empty. (en)
func firstHeaderValue(hdr map[string][]string, key, def string) string {
	if hdr == nil {
		return def
	}
	if vs, ok := hdr[key]; ok && len(vs) > 0 {
		return vs[0]
	}
	return def
}

var (
	sessionsMu       sync.RWMutex
	sessionsByDomain = make(map[string]*dtlsSessionWrapper)
)

// statusRecorder 는 HTTP 응답 상태 코드를 캡처하기 위한 래퍼입니다.
// Prometheus 메트릭에서 status 라벨을 기록하는 데 사용합니다.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// hopGateOwnedHeaders 는 HopGate 서버가 스스로 관리하는 응답 헤더 목록입니다. (ko)
// hopGateOwnedHeaders lists response headers that are owned by the HopGate server. (en)
var hopGateOwnedHeaders = map[string]struct{}{
	"X-HopGate-Server":          {},
	"Strict-Transport-Security": {},
	"X-Content-Type-Options":    {},
	"Referrer-Policy":           {},
}

// writeErrorPage 는 주요 HTTP 에러 코드(400/404/500/525)에 대해 정적 HTML 에러 페이지를 렌더링합니다. (ko)
// writeErrorPage renders static HTML error pages for key HTTP error codes (400/404/500/525). (en)
//
// 템플릿 로딩 우선순위: (ko)
//  1. HOP_ERROR_PAGES_DIR/<status>.html (또는 ./errors/<status>.html) (ko)
//  2. go:embed 로 내장된 templates/<status>.html (ko)
//
// Template loading priority: (en)
//  1. HOP_ERROR_PAGES_DIR/<status>.html (or ./errors/<status>.html) (en)
//  2. go:embed'ed templates/<status>.html (en)
func writeErrorPage(w http.ResponseWriter, r *http.Request, status int) {
	// 공통 보안/식별 헤더를 best-effort 로 설정합니다. (ko)
	// Configure common security and identity headers (best-effort). (en)
	if r != nil {
		setSecurityAndIdentityHeaders(w, r)
	}

	// Delegates actual HTML rendering to internal/errorpages. (en)
	// 실제 HTML 렌더링은 internal/errorpages 패키지에 위임합니다. (ko)
	errorpages.Render(w, r, status)
}

// setSecurityAndIdentityHeaders 는 HopGate 에서 공통으로 추가하는 보안/식별 헤더를 설정합니다. (ko)
// setSecurityAndIdentityHeaders configures common security and identity headers for HopGate. (en)
func setSecurityAndIdentityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()

	// HopGate 로 구성된 서버임을 나타내는 식별 헤더 (ko)
	// Header to indicate that this server is powered by HopGate. (en)
	h.Set("X-HopGate-Server", "hop-gate")

	// 기본 보안 헤더 설정 (ko)
	// Basic security headers (best-effort). (en)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// HTTPS 요청에 대해서만 HSTS 헤더를 추가합니다. (ko)
	// Only send HSTS for HTTPS requests. (en)
	if r != nil && r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
}

// hostDomainHandler 는 HOP_SERVER_DOMAIN 에 지정된 도메인으로만 요청을 허용하는 래퍼입니다.
// Host 헤더에서 포트를 제거한 뒤 소문자 비교를 수행합니다.
func hostDomainHandler(allowedDomain string, logger logging.Logger, next http.Handler) http.Handler {
	allowed := strings.ToLower(strings.TrimSpace(allowedDomain))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed != "" {
			host := r.Host
			if i := strings.Index(host, ":"); i != -1 {
				host = host[:i]
			}
			host = strings.ToLower(strings.TrimSpace(host))
			if host != allowed {
				logger.Warn("rejecting request due to mismatched host", logging.Fields{
					"allowed_domain": allowed,
					"request_host":   host,
					"path":           r.URL.Path,
				})
				// 메트릭/관리용 엔드포인트에 대해 호스트가 다르면 404 페이지로 응답하여 노출을 최소화합니다. (ko)
				// For metrics/admin endpoints, respond with a 404 page when host mismatches to reduce exposure. (en)
				writeErrorPage(w, r, http.StatusNotFound)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func registerSessionForDomain(domain string, sess dtls.Session, logger logging.Logger) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return
	}
	w := &dtlsSessionWrapper{
		sess:           sess,
		bufferedReader: bufio.NewReaderSize(sess, protocol.GetDTLSReadBufferSize()),
	}
	sessionsMu.Lock()
	sessionsByDomain[d] = w
	sessionsMu.Unlock()

	logger.Info("registered dtls session for domain", logging.Fields{
		"domain": d,
		"sid":    sess.ID(),
	})
}

func getSessionForHost(host string) *dtlsSessionWrapper {
	// host may contain port (e.g. "example.com:443"); strip port.
	h := host
	if i := strings.Index(h, ":"); i != -1 {
		h = h[:i]
	}
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return nil
	}
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	return sessionsByDomain[h]
}

func newHTTPHandler(logger logging.Logger, proxyTimeout time.Duration) http.Handler {
	// ACME webroot (for HTTP-01) is read from env; must match HOP_ACME_WEBROOT used by lego.
	webroot := strings.TrimSpace(os.Getenv("HOP_ACME_WEBROOT"))

	// HOP_SERVER_DOMAIN 은 관리/제어용 도메인으로 사용되며, 프록시 대상 도메인이 아닙니다.
	// 이 도메인으로 직접 접근하는 일반 요청은 400 Bad Request 로 응답해야 합니다. (ko)
	// HOP_SERVER_DOMAIN is used as the control/admin domain and is not a proxied
	// origin. Plain HTTP requests to this host should return 400 Bad Request. (en)
	allowedDomain := strings.ToLower(strings.TrimSpace(os.Getenv("HOP_SERVER_DOMAIN")))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// NOTE: /__hopgate_assets__/ 경로는 DTLS/백엔드와 무관하게 항상 정적 에셋만 서빙해야 합니다. (ko)
		//       이 핸들러(newHTTPHandler)는 일반 프록시 경로(/)에만 사용되어야 하지만,
		//       혹시라도 라우팅/구성이 꼬여서 이쪽으로 들어오는 경우를 방지하기 위해
		//       /__hopgate_assets__/ 요청은 여기서도 강제로 정적 핸들러로 처리합니다. (ko)
		//
		//       The /__hopgate_assets__/ path must always serve static assets independently
		//       of DTLS/backend state. This handler is intended for the generic proxy path (/),
		//       but as a safety net, we short-circuit asset requests here as well. (en)
		if strings.HasPrefix(r.URL.Path, "/__hopgate_assets__/") {
			if sub, err := stdfs.Sub(errorpages.AssetsFS, "assets"); err == nil {
				staticFS := http.FileServer(http.FS(sub))
				http.StripPrefix("/__hopgate_assets__/", staticFS).ServeHTTP(w, r)
				return
			}
			// embed FS 가 초기화되지 않은 비정상 상황에서는 500 에러 페이지로 폴백합니다. (ko)
			// If embedded FS is not available for some reason, fall back to a 500 error page. (en)
			writeErrorPage(w, r, http.StatusInternalServerError)
			return
		}

		start := time.Now()
		method := r.Method

		// 상태 코드 캡처를 위한 래퍼
		sr := &statusRecorder{
			ResponseWriter: w,
			status:         http.StatusOK,
		}
		// 보안/식별 헤더를 공통으로 설정합니다. (ko)
		// Configure common security and identity headers. (en)
		setSecurityAndIdentityHeaders(sr, r)

		log := logger.With(logging.Fields{
			"component": "http_entry",
			"method":    method,
			"url":       r.URL.String(),
			"host":      r.Host,
		})
		log.Info("incoming http request", nil)

		// 요청 단위 Prometheus 메트릭 기록
		defer func() {
			elapsed := time.Since(start).Seconds()
			statusCode := sr.status
			observability.HTTPRequestsTotal.WithLabelValues(method, strconv.Itoa(statusCode)).Inc()
			observability.HTTPRequestDurationSeconds.WithLabelValues(method).Observe(elapsed)
		}()

		// 1. ACME HTTP-01 webroot handling
		// /.well-known/acme-challenge/{token} 는 HOP_ACME_WEBROOT 디렉터리에서 정적 파일로 서빙합니다.
		if webroot != "" && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			token := strings.Trim(r.URL.Path, "/")
			if token == "" {
				observability.ProxyErrorsTotal.WithLabelValues("acme_http01_error").Inc()
				writeErrorPage(sr, r, http.StatusBadRequest)
				return
			}
			filePath := filepath.Join(webroot, token)

			log := logger.With(logging.Fields{
				"component": "acme_http01",
				"host":      r.Host,
				"token":     token,
				"path":      r.URL.Path,
				"file":      filePath,
			})
			log.Info("serving acme http-01 challenge", nil)

			f, err := os.Open(filePath)
			if err != nil {
				log.Error("failed to open acme challenge file", logging.Fields{
					"error": err.Error(),
				})
				observability.ProxyErrorsTotal.WithLabelValues("acme_http01_error").Inc()
				writeErrorPage(sr, r, http.StatusNotFound)
				return
			}
			defer f.Close()

			// ACME challenge 응답은 일반적으로 text/plain.
			sr.Header().Set("Content-Type", "text/plain")
			if _, err := io.Copy(sr, f); err != nil {
				log.Error("failed to write acme challenge response", logging.Fields{
					"error": err.Error(),
				})
				observability.ProxyErrorsTotal.WithLabelValues("acme_http01_error").Inc()
			}
			return
		}

		// 2. 일반 HTTP 요청은 DTLS 를 통해 클라이언트로 포워딩
		// 간단한 서비스 이름 결정: 우선 "web" 고정, 추후 Router 도입 시 개선.
		serviceName := "web"

		// Host 헤더에서 포트를 제거하고 소문자로 정규화합니다.
		host := r.Host
		if i := strings.Index(host, ":"); i != -1 {
			host = host[:i]
		}
		hostLower := strings.ToLower(strings.TrimSpace(host))

		// HOP_SERVER_DOMAIN 로 들어온 일반 요청은 프록시 대상이 아니므로 400 으로 응답합니다. (ko)
		// Plain requests to HOP_SERVER_DOMAIN are not proxied and should return 400. (en)
		if allowedDomain != "" && hostLower == allowedDomain {
			log.Warn("request to control domain is not proxied", logging.Fields{
				"host":           r.Host,
				"allowed_domain": allowedDomain,
				"path":           r.URL.Path,
			})
			observability.ProxyErrorsTotal.WithLabelValues("invalid_control_domain_request").Inc()
			writeErrorPage(sr, r, http.StatusBadRequest)
			return
		}

		sessWrapper := getSessionForHost(hostLower)
		if sessWrapper == nil {
			log.Warn("no dtls session for host", logging.Fields{
				"host": r.Host,
			})
			observability.ProxyErrorsTotal.WithLabelValues("no_dtls_session").Inc()
			// 등록되지 않았거나 활성 세션이 없는 도메인으로의 요청은 404 로 응답합니다. (ko)
			// Requests for hosts without an active DTLS session return 404. (en)
			writeErrorPage(sr, r, http.StatusNotFound)
			return
		}

		// 원본 클라이언트 IP를 X-Forwarded-For / X-Real-IP 헤더로 전달합니다. (ko)
		// Forward original client IP via X-Forwarded-For / X-Real-IP headers. (en)
		if r.RemoteAddr != "" {
			remoteIP := r.RemoteAddr
			if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				remoteIP = ip
			}
			if remoteIP != "" {
				// X-Forwarded-For 는 기존 값 뒤에 원본 IP를 추가합니다. (ko)
				// Append original IP to X-Forwarded-For if present. (en)
				if prior := r.Header.Get("X-Forwarded-For"); prior == "" {
					r.Header.Set("X-Forwarded-For", remoteIP)
				} else {
					r.Header.Set("X-Forwarded-For", prior+", "+remoteIP)
				}
				// X-Real-IP 가 비어있는 경우에만 설정합니다. (ko)
				// Set X-Real-IP only if it is not already set. (en)
				if r.Header.Get("X-Real-IP") == "" {
					r.Header.Set("X-Real-IP", remoteIP)
				}
			}
		}

		// r.Body 는 ForwardHTTP 내에서 읽고 닫지 않으므로 여기서 닫기
		defer r.Body.Close()

		// 서버 측에서 DTLS → 클라이언트 → 로컬 서비스까지의 전체 왕복 시간을 제한하기 위해
		// 요청 컨텍스트에 타임아웃을 적용합니다. 기본값은 15초이며,
		// HOP_SERVER_PROXY_TIMEOUT_SECONDS 로 재정의할 수 있습니다. (ko)
		// Apply an overall timeout (default 15s, configurable via
		// HOP_SERVER_PROXY_TIMEOUT_SECONDS) to the DTLS forward path so that
		// excessively slow backends surface as gateway timeouts. (en)
		ctx := r.Context()
		if proxyTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, proxyTimeout)
			defer cancel()
		}

		type forwardResult struct {
			resp *protocol.Response
			err  error
		}
		resultCh := make(chan forwardResult, 1)

		go func() {
			select {
			case <-ctx.Done():
				// Context cancelled, do not proceed.
				return
			default:
				resp, err := sessWrapper.ForwardHTTP(ctx, logger, r, serviceName)
				resultCh <- forwardResult{resp: resp, err: err}
			}
		}()

		var protoResp *protocol.Response

		select {
		case <-ctx.Done():
			log.Error("forward over dtls timed out", logging.Fields{
				"timeout_seconds": int64(proxyTimeout.Seconds()),
				"error":           ctx.Err().Error(),
			})
			observability.ProxyErrorsTotal.WithLabelValues("dtls_forward_timeout").Inc()
			writeErrorPage(sr, r, errorpages.StatusGatewayTimeout)
			return

		case res := <-resultCh:
			if res.err != nil {
				log.Error("forward over dtls failed", logging.Fields{
					"error": res.err.Error(),
				})
				observability.ProxyErrorsTotal.WithLabelValues("dtls_forward_failed").Inc()
				writeErrorPage(sr, r, errorpages.StatusTLSHandshakeFailed)
				return
			}
			protoResp = res.resp
		}

		// 응답 헤더/바디 복원
		for k, vs := range protoResp.Header {
			// HopGate 가 소유한 보안/식별 헤더는 백엔드 값 대신 서버 값만 사용합니다. (ko)
			// For security/identity headers owned by HopGate, ignore backend values. (en)
			if _, ok := hopGateOwnedHeaders[http.CanonicalHeaderKey(k)]; ok {
				continue
			}
			for _, v := range vs {
				sr.Header().Add(k, v)
			}
		}
		if protoResp.Status == 0 {
			protoResp.Status = http.StatusOK
		}
		sr.WriteHeader(protoResp.Status)
		if len(protoResp.Body) > 0 {
			if _, err := sr.Write(protoResp.Body); err != nil {
				log.Warn("failed to write http response body", logging.Fields{
					"error": err.Error(),
				})
			}
		}

		log.Info("http request completed", logging.Fields{
			"status":       protoResp.Status,
			"elapsed_ms":   time.Since(start).Milliseconds(),
			"service_name": serviceName,
		})
	})
}

func main() {
	logger := logging.NewStdJSONLogger("server")

	// 1. 서버 설정 로드 (.env + 환경변수)
	// internal/config 패키지가 .env 를 먼저 읽고, 이미 설정된 OS 환경변수를 우선시합니다.
	cfg, err := config.LoadServerConfigFromEnv()
	if err != nil {
		logger.Error("failed to load server config from env", logging.Fields{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	// 2. 필수 환경 변수 유효성 검사 (.env 포함; OS 환경변수가 우선)
	httpListenEnv := getEnvOrPanic(logger, "HOP_SERVER_HTTP_LISTEN")
	httpsListenEnv := getEnvOrPanic(logger, "HOP_SERVER_HTTPS_LISTEN")
	dtlsListenEnv := getEnvOrPanic(logger, "HOP_SERVER_DTLS_LISTEN")
	domainEnv := getEnvOrPanic(logger, "HOP_SERVER_DOMAIN")
	debugEnv := getEnvOrPanic(logger, "HOP_SERVER_DEBUG")

	// 디버깅 플래그 형식 확인
	if debugEnv != "true" && debugEnv != "false" {
		logger.Error("invalid value for HOP_SERVER_DEBUG; must be 'true' or 'false'", logging.Fields{
			"env":   "HOP_SERVER_DEBUG",
			"value": debugEnv,
		})
		os.Exit(1)
	}

	// 유효성 검사 결과를 구조화 로그로 출력
	logger.Info("validated server env vars", logging.Fields{
		"HOP_SERVER_HTTP_LISTEN":  httpListenEnv,
		"HOP_SERVER_HTTPS_LISTEN": httpsListenEnv,
		"HOP_SERVER_DTLS_LISTEN":  dtlsListenEnv,
		"HOP_SERVER_DOMAIN":       domainEnv,
		"HOP_SERVER_DEBUG":        debugEnv,
	})

	// Prometheus 메트릭 등록
	observability.MustRegister()

	logger.Info("hop-gate server starting", logging.Fields{
		"stack":        "prometheus-loki-grafana",
		"version":      version,
		"http_listen":  cfg.HTTPListen,
		"https_listen": cfg.HTTPSListen,
		"dtls_listen":  cfg.DTLSListen,
		"domain":       cfg.Domain,
		"debug":        cfg.Debug,
	})

	ctx := context.Background()

	// 2. PostgreSQL 연결 및 스키마 초기화 (ent 기반)
	dbClient, err := store.OpenPostgresFromEnv(ctx, logger)
	if err != nil {
		logger.Error("failed to init postgres for admin/domain store", logging.Fields{
			"error": err.Error(),
		})
		os.Exit(1)
	}
	defer dbClient.Close()

	logger.Info("postgres connected and schema ready", logging.Fields{
		"component": "store",
	})

	// 3.1 Admin Plane: DomainService + Admin HTTP handler 구성
	adminService := admin.NewDomainService(logger, dbClient)

	// Admin API 키는 환경변수에서 읽어옵니다.
	// - HOP_ADMIN_API_KEY 가 비어 있으면, 모든 Admin API 요청이 거부됩니다.
	adminAPIKey := strings.TrimSpace(os.Getenv("HOP_ADMIN_API_KEY"))
	if adminAPIKey == "" {
		logger.Warn("HOP_ADMIN_API_KEY is not set; admin API will reject all requests", logging.Fields{
			"component": "admin_api",
		})
	}

	// 3. TLS 설정: ACME(lego)로 인증서를 관리하고, Debug 모드에서는 DTLS에는 self-signed 를 사용하되
	// ACME 는 항상 시도하되 Staging 모드로 동작하도록 합니다.
	// 3. TLS setup: manage certificates via ACME (lego); in debug mode DTLS uses self-signed
	// but ACME is still attempted in staging mode.
	var tlsCfg *tls.Config

	// ACME 를 위해 사용할 도메인 목록 구성
	var domains []string
	if cfg.Domain != "" {
		domains = append(domains, cfg.Domain)
	}
	domains = append(domains, cfg.ProxyDomains...)

	// Debug 모드에서는 반드시 Staging CA 를 사용하도록 강제
	if cfg.Debug {
		_ = os.Setenv("HOP_ACME_USE_STAGING", "true")
	}

	// HOP_ACME_STANDALONE_ONLY=true 인 경우, ACME 인증서만 발급/갱신하고 프로세스를 종료합니다.
	// 이 모드는 HTTP/DTLS 서버를 띄우지 않고 lego(ACME client)만 단독으로 실행할 때 사용합니다.
	standaloneOnly := func() bool {
		v := strings.ToLower(strings.TrimSpace(os.Getenv("HOP_ACME_STANDALONE_ONLY")))
		switch v {
		case "1", "true", "yes", "y", "on":
			return true
		default:
			return false
		}
	}()
	if standaloneOnly {
		logger.Info("running ACME standalone-only mode", logging.Fields{
			"domains":     domains,
			"use_staging": cfg.Debug,
		})

		// ACME(lego) 매니저 초기화: 도메인 DNS 확인 + 인증서 확보/갱신 + 캐시 저장
		// 이 호출이 끝나면 해당 도메인에 대한 인증서가 HOP_ACME_CACHE_DIR 에 준비되어 있어야 합니다.
		acmeCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()

		if _, err := acme.NewLegoManagerFromEnv(acmeCtx, logger, domains); err != nil {
			logger.Error("acme standalone mode failed", logging.Fields{
				"error":   err.Error(),
				"domains": domains,
			})
			os.Exit(1)
		}

		logger.Info("acme standalone mode completed successfully, exiting process", logging.Fields{
			"domains": domains,
		})
		return
	}

	// ACME(lego) 매니저 초기화: 도메인 DNS 확인 + 인증서 확보/갱신 + 캐시 저장
	acmeMgr, err := acme.NewLegoManagerFromEnv(ctx, logger, domains)
	if err != nil {
		logger.Error("failed to initialize ACME lego manager", logging.Fields{
			"error":   err.Error(),
			"domains": domains,
		})
		os.Exit(1)
	}
	acmeTLSCfg := acmeMgr.TLSConfig()

	logger.Info("acme tls config initialized", logging.Fields{
		"domains":     domains,
		"use_staging": cfg.Debug,
	})

	if cfg.Debug {
		// Debug 모드: DTLS 자체는 self-signed localhost 인증서를 사용하지만,
		// ACME Staging 을 통해 실제 도메인 인증서도 동시에 관리합니다.
		tlsCfg, err = dtls.NewSelfSignedLocalhostConfig()
		if err != nil {
			logger.Error("failed to create self-signed localhost cert", logging.Fields{
				"error": err.Error(),
			})
			os.Exit(1)
		}
		logger.Warn("using self-signed localhost certificate for DTLS (debug mode)", logging.Fields{
			"note": "acme is running in staging mode; do not use this configuration in production",
		})
	} else {
		// Production 모드: DTLS/HTTPS 모두 ACME 인증서를 직접 사용
		tlsCfg = acmeTLSCfg
	}

	// DTLS 서버는 HOP_SERVER_DOMAIN 으로 지정된 도메인에 대한 연결만 수락해야 합니다.
	// 이를 위해 GetCertificate 를 래핑하여 SNI 검증 로직을 추가합니다.
	// 주의: HTTPS 서버용 tlsCfg 에 영향을 주지 않도록 Clone()을 사용합니다.
	dtlsTLSConfig := tlsCfg.Clone()
	if cfg.Domain != "" {
		nextGetCert := dtlsTLSConfig.GetCertificate
		dtlsTLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// SNI 검증: 설정된 도메인과 일치하지 않으면 핸드셰이크 거부
			// ServerName이 비어있는 경우(클라이언트가 SNI 미전송 시)는 검증을 건너뜁니다.
			if hello.ServerName != "" && !strings.EqualFold(hello.ServerName, cfg.Domain) {
				return nil, fmt.Errorf("dtls: invalid SNI %q, expected %q", hello.ServerName, cfg.Domain)
			}

			// 기존 로직 수행
			if nextGetCert != nil {
				return nextGetCert(hello)
			}
			// Debug 모드 등에서 GetCertificate 가 없는 경우 Certificates 필드 사용
			if len(dtlsTLSConfig.Certificates) > 0 {
				return &dtlsTLSConfig.Certificates[0], nil
			}
			return nil, fmt.Errorf("dtls: no certificate found for %q", hello.ServerName)
		}
	}

	// 4. DTLS 서버 리스너 생성 (pion/dtls 기반)
	dtlsServer, err := dtls.NewPionServer(dtls.PionServerConfig{
		Addr:      cfg.DTLSListen,
		TLSConfig: dtlsTLSConfig,
	})
	if err != nil {
		logger.Error("failed to start dtls server", logging.Fields{
			"error": err.Error(),
		})
		os.Exit(1)
	}
	defer dtlsServer.Close()

	logger.Info("dtls server listening", logging.Fields{
		"addr": cfg.DTLSListen,
	})

	// 5. HTTP / HTTPS 서버 시작
	// 프록시 타임아웃은 HOP_SERVER_PROXY_TIMEOUT_SECONDS(초 단위) 로 설정할 수 있으며,
	// 기본값은 15초입니다. (ko)
	// The proxy timeout can be configured via HOP_SERVER_PROXY_TIMEOUT_SECONDS
	// (in seconds); the default is 15 seconds. (en)
	proxyTimeout := 15 * time.Second
	if v := strings.TrimSpace(os.Getenv("HOP_SERVER_PROXY_TIMEOUT_SECONDS")); v != "" {
		if secs, err := strconv.Atoi(v); err != nil {
			logger.Warn("invalid HOP_SERVER_PROXY_TIMEOUT_SECONDS format, using default", logging.Fields{
				"value": v,
				"error": err,
			})
		} else if secs <= 0 {
			logger.Warn("HOP_SERVER_PROXY_TIMEOUT_SECONDS must be positive, using default", logging.Fields{
				"value": v,
			})
		}
	}
	logger.Info("http proxy timeout configured", logging.Fields{
		"timeout_seconds": int64(proxyTimeout.Seconds()),
	})

	httpHandler := newHTTPHandler(logger, proxyTimeout)

	// Prometheus /metrics 엔드포인트 및 메인 핸들러를 위한 mux 구성
	httpMux := http.NewServeMux()
	allowedDomain := strings.ToLower(strings.TrimSpace(cfg.Domain))

	// __hopgate_assets__ prefix:
	// HopGate 서버가 직접 Tailwind CSS, 로고 등 정적 에셋을 서빙하기 위한 경로입니다. (ko)
	// This prefix is used for static assets (Tailwind CSS, logos, etc.) served directly by HopGate. (en)
	//
	// 우선순위: (ko)
	//   1) HOP_ERROR_ASSETS_DIR 가 설정되어 있으면 해당 디렉터리 (디스크 기반)
	//   2) 없으면 internal/errorpages/assets 에 내장된 go:embed 에셋 사용
	//
	// Priority: (en)
	//   1) HOP_ERROR_ASSETS_DIR if set (disk-based)
	//   2) Otherwise, use go:embed'ed assets under internal/errorpages/assets
	assetDir := strings.TrimSpace(os.Getenv("HOP_ERROR_ASSETS_DIR"))
	if assetDir != "" {
		fs := http.FileServer(http.Dir(assetDir))
		httpMux.Handle("/__hopgate_assets/",
			hostDomainHandler(allowedDomain, logger,
				http.StripPrefix("/__hopgate_assets/", fs),
			),
		)
	} else {
		// Embedded assets under internal/errorpages/assets.
		if sub, err := stdfs.Sub(errorpages.AssetsFS, "assets"); err == nil {
			staticFS := http.FileServer(http.FS(sub))
			httpMux.Handle("/__hopgate_assets/",
				hostDomainHandler(allowedDomain, logger,
					http.StripPrefix("/__hopgate_assets/", staticFS),
				),
			)
		} else {
			logger.Warn("failed to init embedded assets filesystem", logging.Fields{
				"component": "error_assets",
				"error":     err.Error(),
			})
		}
	}

	// /metrics 는 HOP_SERVER_DOMAIN 에 지정된 도메인으로만 접근 가능하도록 제한합니다.
	httpMux.Handle("/metrics", hostDomainHandler(allowedDomain, logger, promhttp.Handler()))

	// Admin Plane HTTP mux: /api/v1/admin/* 경로를 처리합니다.
	// - Authorization: Bearer {HOP_ADMIN_API_KEY} 헤더를 사용해 인증합니다.
	adminHandler := admin.NewHandler(logger, adminAPIKey, adminService)
	adminMux := http.NewServeMux()
	adminHandler.RegisterRoutes(adminMux)
	httpMux.Handle("/api/v1/admin/", hostDomainHandler(allowedDomain, logger, adminMux))

	// 기본 HTTP → DTLS Proxy 엔트리 포인트
	httpMux.Handle("/", httpHandler)

	// HTTP: 평문 포트
	httpSrv := &http.Server{
		Addr:    cfg.HTTPListen,
		Handler: httpMux,
	}
	go func() {
		logger.Info("http server listening", logging.Fields{
			"addr": cfg.HTTPListen,
		})
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", logging.Fields{
				"error": err.Error(),
			})
		}
	}()

	// HTTPS: ACME 기반 TLS 사용 (debug 모드에서도 ACME tls config 사용 가능)
	httpsSrv := &http.Server{
		Addr:      cfg.HTTPSListen,
		Handler:   httpMux,
		TLSConfig: acmeTLSCfg,
	}
	go func() {
		logger.Info("https server listening", logging.Fields{
			"addr": cfg.HTTPSListen,
		})
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Error("https server error", logging.Fields{
				"error": err.Error(),
			})
		}
	}()

	// 6. 도메인 검증기 준비 (ent + PostgreSQL 기반 실제 구현)
	// Admin Plane 에서 관리하는 Domain 테이블을 사용해 (domain, client_api_key) 조합을 검증합니다.
	domainValidator := admin.NewEntDomainValidator(logger, dbClient)

	// DTLS 핸드셰이크 단계에서는 클라이언트가 제시한 도메인의 DNS(A/AAAA)가
	// HOP_ACME_EXPECT_IPS 에 설정된 IP들 중 하나 이상을 가리키는지 추가로 검증합니다. (ko)
	// During DTLS handshake, additionally verify that the presented domain resolves
	// (via A/AAAA) to at least one IP configured in HOP_ACME_EXPECT_IPS. (en)
	// EXPECT_IPS 가 비어 있으면 DNS 기반 검증은 생략하고 DB 검증만 수행합니다. (ko)
	// If EXPECT_IPS is empty, only DB-based validation is performed. (en)
	expectedHandshakeIPs := parseExpectedIPsFromEnv(logger, "HOP_ACME_EXPECT_IPS")
	var validator dtls.DomainValidator = &domainGateValidator{
		expectedIPs: expectedHandshakeIPs,
		inner:       domainValidator,
		logger:      logger,
	}

	// 7. DTLS Accept 루프 + Handshake
	for {
		sess, err := dtlsServer.Accept()
		if err != nil {
			logger.Error("dtls accept failed", logging.Fields{
				"error": err.Error(),
			})
			continue
		}

		// 각 세션별로 goroutine 에서 핸드셰이크 및 후속 처리를 수행합니다.
		go func(s dtls.Session) {
			// NOTE: 세션은 HTTP↔DTLS 터널링에 계속 사용해야 하므로 이곳에서 Close 하지 않습니다.
			// 세션 종료/타임아웃 관리는 별도의 세션 매니저(TODO)에서 담당해야 합니다.
			hsRes, err := dtls.PerformServerHandshake(ctx, s, validator, logger)
			if err != nil {
				// 핸드셰이크 실패 메트릭 기록
				observability.DTLSHandshakesTotal.WithLabelValues("failure").Inc()

				// PerformServerHandshake 내부에서 이미 상세 로그를 남기므로 여기서는 요약만 기록합니다.
				logger.Warn("dtls handshake failed", logging.Fields{
					"session_id": s.ID(),
					"error":      err.Error(),
				})
				// 핸드셰이크 실패 시 세션을 명시적으로 종료하여 invalid SNI 등 오류에서
				// 연결이 열린 채로 남지 않도록 합니다.
				_ = s.Close()
				return
			}

			// Handshake 성공 메트릭 기록
			observability.DTLSHandshakesTotal.WithLabelValues("success").Inc()

			// Handshake 성공: 서버 측은 어떤 도메인이 연결되었는지 알 수 있습니다.
			logger.Info("dtls handshake completed", logging.Fields{
				"session_id": s.ID(),
				"domain":     hsRes.Domain,
			})

			// Handshake 가 완료된 세션을 도메인에 매핑해 HTTP 요청 시 사용할 수 있도록 등록합니다.
			registerSessionForDomain(hsRes.Domain, s, logger)

			// Handshake 가 정상적으로 끝난 이후, 실제로 해당 도메인에 대해 ACME 인증서를 확보/연장합니다.
			// Debug 모드에서도 ACME 는 항상 시도하지만, 위에서 HOP_ACME_USE_STAGING=true 로 설정되어
			// Staging CA 를 사용하게 됩니다.
			if hsRes.Domain != "" {
				go func(domain string) {
					acmeLogger := logger.With(logging.Fields{
						"component": "acme_post_handshake",
						"domain":    domain,
						"debug":     cfg.Debug,
					})
					if _, err := acme.NewLegoManagerFromEnv(context.Background(), acmeLogger, []string{domain}); err != nil {
						acmeLogger.Error("failed to ensure acme certificate after dtls handshake", logging.Fields{
							"error": err.Error(),
						})
						return
					}
					acmeLogger.Info("acme certificate ensured after dtls handshake", nil)
				}(hsRes.Domain)
			}

			// TODO:
			//   - hsRes.Domain 과 연결된 세션을 proxy 레이어에 등록
			//   - HTTP 요청을 이 세션을 통해 해당 클라이언트로 라우팅
			//   - 세션 생명주기/타임아웃 관리 등
		}(sess)
	}
}
