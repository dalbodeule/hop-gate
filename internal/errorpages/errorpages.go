package errorpages

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// StatusTLSHandshakeFailed is an HTTP-style status code representing
// a TLS/DTLS handshake failure (similar to Cloudflare 525).
// TLS/DTLS 핸드셰이크 실패를 나타내는 HTTP 스타일 상태 코드입니다. (예: 525)
const StatusTLSHandshakeFailed = 525

// StatusGatewayTimeout is an HTTP-style status code representing
// a gateway timeout between HopGate and the backend (similar to 504).
// HopGate 와 백엔드 간 요청이 너무 오래 걸려 타임아웃된 경우를 나타내는 상태 코드입니다. (예: 504)
const StatusGatewayTimeout = http.StatusGatewayTimeout

//go:embed templates/*.html
var embeddedTemplatesFS embed.FS

// AssetsFS embeds static assets (CSS, logos, etc.) for error pages.
// 에러 페이지용 정적 에셋(CSS, 로고 등)을 바이너리에 포함하는 embed FS 입니다.
//
// Expected files (by convention):
//   - assets/errors.css
//   - assets/hop-gate.png
//
//go:embed assets/*
var AssetsFS embed.FS

// Render writes an error page HTML for the given HTTP status code to the response writer.
// If no matching template is found, it falls back to a minimal plain text response.
//
// 주어진 HTTP 상태 코드에 대한 에러 페이지 HTML을 응답에 씁니다.
// 해당 템플릿이 없으면 최소한의 텍스트 응답으로 폴백합니다.
func Render(w http.ResponseWriter, r *http.Request, status int) {
	html, ok := Load(status)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	if !ok {
		// Fallback to a minimal plain text response if no template is available.
		// 템플릿이 없으면 간단한 텍스트 응답으로 대체합니다.
		_, _ = fmt.Fprintf(w, "%d %s", status, http.StatusText(status))
		return
	}

	_, _ = w.Write(html)
}

// Load attempts to load an error page for the given HTTP status code.
//
// Priority:
//  1. $HOP_ERROR_PAGES_DIR/<status>.html (or ./errors/<status>.html if env is empty)
//  2. embedded template: templates/<status>.html
//
// 주어진 HTTP 상태 코드에 대한 에러 페이지를 로드합니다.
//
// 우선순위:
//  1. $HOP_ERROR_PAGES_DIR/<status>.html (env 미설정 시 ./errors/<status>.html)
//  2. 내장 템플릿: templates/<status>.html
func Load(status int) ([]byte, bool) {
	name := fmt.Sprintf("%d.html", status)

	// 1. External directory override (HOP_ERROR_PAGES_DIR, default "./errors").
	// 1. 외부 디렉터리 우선 (HOP_ERROR_PAGES_DIR, 기본값 "./errors").
	dir := strings.TrimSpace(os.Getenv("HOP_ERROR_PAGES_DIR"))
	if dir == "" {
		dir = "./errors"
	}
	p := filepath.Join(dir, name)
	if data, err := os.ReadFile(p); err == nil {
		return data, true
	}

	// 2. Embedded default templates.
	// 2. 내장 기본 템플릿.
	p = filepath.Join("templates", name)
	if data, err := embeddedTemplatesFS.ReadFile(p); err == nil {
		return data, true
	}

	return nil, false
}
