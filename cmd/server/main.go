package main

import (
	"context"
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
	"github.com/dalbodeule/hop-gate/internal/errorpages"
	"github.com/dalbodeule/hop-gate/internal/logging"
	"github.com/dalbodeule/hop-gate/internal/observability"
	"github.com/dalbodeule/hop-gate/internal/store"
	"github.com/dalbodeule/hop-gate/internal/tunnel"
)

var version = "dev"

func getEnvOrPanic(logger logging.Logger, key string) string {
	value, exists := os.LookupEnv(key)
	if !exists || strings.TrimSpace(value) == "" {
		logger.Error("missing required environment variable", logging.Fields{"env": key})
		os.Exit(1)
	}
	return value
}

var (
	tunnelsMu       sync.RWMutex
	tunnelsByDomain = make(map[string]forwardTunnel)
)

type forwardTunnel interface {
	ForwardHTTP(context.Context, logging.Logger, *http.Request, string) (*tunnel.Response, error)
}

func registerTunnelForDomain(domain string, sess forwardTunnel, logger logging.Logger) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" || sess == nil {
		return ""
	}
	tunnelsMu.Lock()
	tunnelsByDomain[d] = sess
	tunnelsMu.Unlock()
	logger.Info("registered yamux tunnel for domain", logging.Fields{"domain": d})
	return d
}

func unregisterTunnelForDomain(domain string, sess forwardTunnel, logger logging.Logger) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" || sess == nil {
		return
	}
	tunnelsMu.Lock()
	if current := tunnelsByDomain[d]; current == sess {
		delete(tunnelsByDomain, d)
	}
	tunnelsMu.Unlock()
	logger.Info("unregistered yamux tunnel for domain", logging.Fields{"domain": d})
}

func getTunnelForHost(host string) forwardTunnel {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil
	}
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	} else if i := strings.LastIndex(h, ":"); i > -1 && !strings.Contains(h[i+1:], "]") {
		h = h[:i]
	}
	tunnelsMu.RLock()
	defer tunnelsMu.RUnlock()
	return tunnelsByDomain[h]
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

var hopGateOwnedHeaders = map[string]struct{}{
	"X-HopGate-Server":          {},
	"Strict-Transport-Security": {},
	"X-Content-Type-Options":    {},
	"Referrer-Policy":           {},
}

func writeErrorPage(w http.ResponseWriter, r *http.Request, status int) {
	if r != nil {
		setSecurityAndIdentityHeaders(w, r)
	}
	errorpages.Render(w, r, status)
}

func setSecurityAndIdentityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-HopGate-Server", "hop-gate")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	if r != nil && r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
}

func hostDomainHandler(allowedDomain string, logger logging.Logger, next http.Handler) http.Handler {
	allowed := strings.ToLower(strings.TrimSpace(allowedDomain))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed != "" {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			} else {
				host = strings.Trim(host, "[]")
			}
			if !strings.EqualFold(strings.TrimSpace(host), allowed) {
				logger.Warn("rejecting request due to mismatched host", logging.Fields{"allowed_domain": allowed, "request_host": host, "path": r.URL.Path})
				writeErrorPage(w, r, http.StatusNotFound)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
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
		// NOTE: /__hopgate_assets__/ 경로는 백엔드와 무관하게 항상 정적 에셋만 서빙해야 합니다. (ko)
		//       이 핸들러(newHTTPHandler)는 일반 프록시 경로(/)에만 사용되어야 하지만,
		//       혹시라도 라우팅/구성이 꼬여서 이쪽으로 들어오는 경우를 방지하기 위해
		//       /__hopgate_assets__/ 요청은 여기서도 강제로 정적 핸들러로 처리합니다. (ko)
		//
		//       The /__hopgate_assets__/ path must always serve static assets independently
		//       of backend state. This handler is intended for the generic proxy path (/),
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

		// 2. 일반 HTTP 요청은 활성 yamux 터널을 통해 클라이언트로 포워딩합니다. (ko)
		// 2. Regular HTTP requests are forwarded to clients over an active yamux tunnel. (en)
		// 간단한 서비스 이름 결정: 우선 "web" 고정, 추후 Router 도입 시 개선. (ko)
		// For now, use a fixed logical service name "web"; this can be improved with a Router later. (en)
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

		activeTunnel := getTunnelForHost(hostLower)
		if activeTunnel == nil {
			log.Warn("no tunnel for host", logging.Fields{
				"host": r.Host,
			})
			observability.ProxyErrorsTotal.WithLabelValues("no_tunnel_session").Inc()
			// 등록되지 않았거나 활성 터널이 없는 도메인으로의 요청은 404 로 응답합니다. (ko)
			// Requests for hosts without an active tunnel return 404. (en)
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

		// r.Body 는 ForwardHTTP 내에서 읽고 닫지 않으므로 여기서 닫기 (ko)
		// r.Body is consumed inside ForwardHTTP; ensure it is closed here. (en)
		defer r.Body.Close()

		// 서버 측에서 yamux 터널 → 클라이언트 → 로컬 서비스까지의 전체 왕복 시간을 제한하기 위해
		// 요청 컨텍스트에 타임아웃을 적용합니다. 기본값은 15초이며,
		// HOP_SERVER_PROXY_TIMEOUT_SECONDS 로 재정의할 수 있습니다. (ko)
		// Apply an overall timeout (default 15s, configurable via
		// HOP_SERVER_PROXY_TIMEOUT_SECONDS) to the tunnel forward path so that
		// excessively slow backends surface as gateway timeouts. (en)
		ctx := r.Context()
		if proxyTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, proxyTimeout)
			defer cancel()
		}

		type forwardResult struct {
			resp *tunnel.Response
			err  error
		}
		resultCh := make(chan forwardResult, 1)

		go func() {
			select {
			case <-ctx.Done():
				// Context cancelled, do not proceed.
				return
			default:
				resp, err := activeTunnel.ForwardHTTP(ctx, logger, r, serviceName)
				resultCh <- forwardResult{resp: resp, err: err}
			}
		}()

		var protoResp *tunnel.Response

		select {
		case <-ctx.Done():
			log.Error("forward over tunnel timed out", logging.Fields{
				"timeout_seconds": int64(proxyTimeout.Seconds()),
				"error":           ctx.Err().Error(),
			})
			observability.ProxyErrorsTotal.WithLabelValues("tunnel_forward_timeout").Inc()
			writeErrorPage(sr, r, errorpages.StatusGatewayTimeout)
			return

		case res := <-resultCh:
			if res.err != nil {
				log.Error("forward over tunnel failed", logging.Fields{
					"error": res.err.Error(),
				})
				observability.ProxyErrorsTotal.WithLabelValues("tunnel_forward_failed").Inc()
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
		"HOP_SERVER_DOMAIN":       domainEnv,
		"HOP_SERVER_DEBUG":        debugEnv,
	})

	// Prometheus 메트릭 등록
	observability.MustRegister()

	logger.Info("hop-gate server starting", logging.Fields{
		"stack":         "prometheus-loki-grafana",
		"version":       version,
		"http_listen":   cfg.HTTPListen,
		"https_listen":  cfg.HTTPSListen,
		"tunnel_listen": cfg.TunnelListen,
		"domain":        cfg.Domain,
		"debug":         cfg.Debug,
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

	// yamux control stream에서 사용할 도메인 검증기 구성. (ko)
	// Construct domain validator for the yamux control stream. (en)
	domainValidator := admin.NewEntDomainValidator(logger, dbClient)

	var domains []string
	if cfg.Domain != "" {
		domains = append(domains, cfg.Domain)
	}
	domains = append(domains, cfg.ProxyDomains...)
	if cfg.Debug {
		_ = os.Setenv("HOP_ACME_USE_STAGING", "true")
	}
	standaloneOnly := strings.EqualFold(strings.TrimSpace(os.Getenv("HOP_ACME_STANDALONE_ONLY")), "true")
	if standaloneOnly {
		acmeCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if _, err := acme.NewLegoManagerFromEnv(acmeCtx, logger, domains); err != nil {
			logger.Error("acme standalone mode failed", logging.Fields{"error": err.Error()})
			os.Exit(1)
		}
		return
	}
	acmeMgr, err := acme.NewLegoManagerFromEnv(ctx, logger, domains)
	if err != nil {
		logger.Error("failed to initialize ACME lego manager", logging.Fields{"error": err.Error(), "domains": domains})
		os.Exit(1)
	}
	acmeTLSCfg := acmeMgr.TLSConfig()

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

	// 기본 HTTP → yamux Proxy 엔트리 포인트
	httpMux.Handle("/", httpHandler)

	go func() {
		if err := serveYamuxTunnel(context.Background(), cfg.TunnelListen, acmeTLSCfg, logger, domainValidator); err != nil {
			logger.Error("yamux tunnel server stopped", logging.Fields{"error": err.Error()})
		}
	}()
	logger.Info("yamux transport enabled", logging.Fields{"listen": cfg.TunnelListen})

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
	if len(acmeTLSCfg.NextProtos) == 0 {
		acmeTLSCfg.NextProtos = []string{"h2", "http/1.1"}
	}

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

	// yamux 및 HTTP/HTTPS 서버 goroutine을 유지합니다. (ko)
	// Keep the yamux and HTTP/HTTPS server goroutines running. (en)
	select {}
}
