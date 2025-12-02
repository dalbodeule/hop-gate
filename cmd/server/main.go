package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

type dtlsSessionWrapper struct {
	sess dtls.Session
	mu   sync.Mutex
}

// domainGateValidator 는 DTLS 핸드셰이크에서 허용된 도메인(HOP_SERVER_DOMAIN)만 통과시키기 위한 래퍼입니다. (ko)
// domainGateValidator wraps another DomainValidator and allows only the configured HOP_SERVER_DOMAIN. (en)
type domainGateValidator struct {
	allowed string
	inner   dtls.DomainValidator
	logger  logging.Logger
}

func (v *domainGateValidator) ValidateDomainAPIKey(ctx context.Context, domain, clientAPIKey string) error {
	d := strings.ToLower(strings.TrimSpace(domain))
	if v.allowed != "" && d != v.allowed {
		if v.logger != nil {
			v.logger.Warn("dtls handshake rejected due to mismatched domain", logging.Fields{
				"expected_domain": v.allowed,
				"received_domain": d,
			})
		}
		return fmt.Errorf("domain %s is not allowed for dtls handshake", domain)
	}
	if v.inner != nil {
		return v.inner.ValidateDomainAPIKey(ctx, domain, clientAPIKey)
	}
	return nil
}

// ForwardHTTP 는 단일 HTTP 요청을 DTLS 세션으로 포워딩하고 응답을 돌려받습니다.
// ForwardHTTP forwards a single HTTP request over the DTLS session and returns the response.
func (w *dtlsSessionWrapper) ForwardHTTP(ctx context.Context, logger logging.Logger, req *http.Request, serviceName string) (*protocol.Response, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}

	// 요청 본문 읽기
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = b
	}

	// 간단한 RequestID 생성 (실제 서비스에서는 UUID 등을 사용하는 것이 좋음)
	requestID := time.Now().UTC().Format("20060102T150405.000000000")

	httpReq := &protocol.Request{
		RequestID:   requestID,
		ClientID:    "", // TODO: 클라이언트 식별자 도입 시 채우기
		ServiceName: serviceName,
		Method:      req.Method,
		URL:         req.URL.String(),
		Header:      req.Header.Clone(),
		Body:        body,
	}

	log := logger.With(logging.Fields{
		"component":  "http_to_dtls",
		"request_id": requestID,
		"method":     req.Method,
		"url":        req.URL.String(),
	})

	log.Info("forwarding http request over dtls", logging.Fields{
		"host":   req.Host,
		"scheme": req.URL.Scheme,
	})

	// HTTP 요청을 Envelope 로 감싸서 전송합니다.
	env := &protocol.Envelope{
		Type:        protocol.MessageTypeHTTP,
		HTTPRequest: httpReq,
	}

	enc := json.NewEncoder(w.sess)
	if err := enc.Encode(env); err != nil {
		log.Error("failed to encode http envelope", logging.Fields{
			"error": err.Error(),
		})
		return nil, err
	}

	// 클라이언트로부터 HTTP 응답 Envelope 를 수신합니다.
	var respEnv protocol.Envelope
	dec := json.NewDecoder(w.sess)
	if err := dec.Decode(&respEnv); err != nil {
		log.Error("failed to decode http envelope", logging.Fields{
			"error": err.Error(),
		})
		return nil, err
	}

	if respEnv.Type != protocol.MessageTypeHTTP || respEnv.HTTPResponse == nil {
		log.Error("received non-http envelope from client", logging.Fields{
			"type": respEnv.Type,
		})
		return nil, fmt.Errorf("unexpected envelope type %q or empty http_response", respEnv.Type)
	}

	protoResp := respEnv.HTTPResponse

	log.Info("received dtls response", logging.Fields{
		"status": protoResp.Status,
		"error":  protoResp.Error,
	})

	return protoResp, nil
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
	w := &dtlsSessionWrapper{sess: sess}
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

func newHTTPHandler(logger logging.Logger) http.Handler {
	// ACME webroot (for HTTP-01) is read from env; must match HOP_ACME_WEBROOT used by lego.
	webroot := strings.TrimSpace(os.Getenv("HOP_ACME_WEBROOT"))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// NOTE: /__hopgate_assets__/ 경로는 DTLS/백엔드와 무관하게 항상 정적 에셋만 서빙해야 합니다. (ko)
		//       이 핸들러(newHTTPHandler)는 일반 프록시 경로(/)에만 사용되어야 하지만,
		//       혹시라도 라우팅/구성이 꼬여서 이쪽으로 들어오는 경우를 방지하기 위해
		//       /__hopgate_assets__/ 요청은 여기서도 강제로 정적 핸들러로 처리합니다. (ko)
		//
		//       The /__hopgate_assets__/ path must always serve static assets independently
		//       of DTLS/backend state. This handler is intended for the generic proxy path (/),
		//       but as a safety net, we short-circuit asset requests here as well. (en)
		if strings.HasPrefix(r.URL.Path, "/__hopgate_assets/") {
			if sub, err := stdfs.Sub(errorpages.AssetsFS, "assets"); err == nil {
				staticFS := http.FileServer(http.FS(sub))
				http.StripPrefix("/__hopgate_assets/", staticFS).ServeHTTP(w, r)
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

		sessWrapper := getSessionForHost(r.Host)
		if sessWrapper == nil {
			log.Warn("no dtls session for host", logging.Fields{
				"host": r.Host,
			})
			observability.ProxyErrorsTotal.WithLabelValues("no_dtls_session").Inc()
			writeErrorPage(sr, r, errorpages.StatusTLSHandshakeFailed)
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

		ctx := r.Context()
		protoResp, err := sessWrapper.ForwardHTTP(ctx, logger, r, serviceName)
		if err != nil {
			log.Error("forward over dtls failed", logging.Fields{
				"error": err.Error(),
			})
			observability.ProxyErrorsTotal.WithLabelValues("dtls_forward_failed").Inc()
			writeErrorPage(sr, r, errorpages.StatusTLSHandshakeFailed)
			return
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

	// Prometheus 메트릭 등록
	observability.MustRegister()

	// 1. 서버 설정 로드 (.env + 환경변수)
	cfg, err := config.LoadServerConfigFromEnv()
	if err != nil {
		logger.Error("failed to load server config from env", logging.Fields{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	logger.Info("hop-gate server starting", logging.Fields{
		"stack":        "prometheus-loki-grafana",
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
	httpHandler := newHTTPHandler(logger)

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

	// 6. 도메인 검증기 준비 (현재는 Dummy 구현, 추후 ent + PostgreSQL 기반으로 교체 예정)
	baseValidator := dtls.DummyDomainValidator{
		Logger: logger,
	}

	// DTLS 핸드셰이크 단계에서 HOP_SERVER_DOMAIN 으로 설정된 도메인만 허용하도록 래핑합니다.
	allowedDomain = strings.ToLower(strings.TrimSpace(cfg.Domain))
	var validator dtls.DomainValidator = &domainGateValidator{
		allowed: allowedDomain,
		inner:   baseValidator,
		logger:  logger,
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
