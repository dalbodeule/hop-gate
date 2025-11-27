package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

// 전역 레지스트리에 등록할 HopGate 메트릭들을 정의합니다.
// Prometheus 기본 네임스페이스를 사용하며, 메트릭 이름에 hopgate_ 접두어를 붙입니다.

var (
	// DTLS 핸드셰이크 총 횟수 (성공/실패 라벨 포함).
	DTLSHandshakesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hopgate_dtls_handshakes_total",
			Help: "Total number of DTLS handshakes, labeled by result.",
		},
		[]string{"result"}, // success, failure
	)

	// HTTP/Proxy 엔드포인트를 통해 들어온 요청 수 (메서드/상태 코드 라벨 포함).
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hopgate_http_requests_total",
			Help: "Total number of HTTP requests handled by the proxy entrypoint, labeled by method and status code.",
		},
		[]string{"method", "status"},
	)

	// HTTP 요청 처리 시간 분포 (메서드 라벨 포함).
	HTTPRequestDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "hopgate_http_request_duration_seconds",
			Help:    "Histogram of HTTP request latencies in seconds at the proxy entrypoint, labeled by method.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	// Proxy 에러 카운터 (에러 유형 라벨 포함).
	ProxyErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hopgate_proxy_errors_total",
			Help: "Total number of proxy-related errors, labeled by error type.",
		},
		[]string{"type"}, // e.g. no_dtls_session, dtls_forward_failed, acme_http01_error
	)
)

// MustRegister 는 위에서 정의한 메트릭들을 전역 Prometheus 레지스트리에 등록합니다.
// 서버 시작 시 한 번만 호출해야 합니다.
func MustRegister() {
	prometheus.MustRegister(
		DTLSHandshakesTotal,
		HTTPRequestsTotal,
		HTTPRequestDurationSeconds,
		ProxyErrorsTotal,
	)
}
