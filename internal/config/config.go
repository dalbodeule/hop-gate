package config

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
)

// LoggingConfig 는 공통 로그 설정을 담습니다.
// Loki push 에 필요한 엔드포인트/인증/정적 라벨 등을 포함합니다.
type LoggingConfig struct {
	Level string     // 예: "debug", "info", "warn", "error"
	Loki  LokiConfig // Loki 관련 설정
}

// LokiConfig 는 Loki HTTP push 설정을 담습니다.
type LokiConfig struct {
	Enable       bool              // true 인 경우 Loki 로도 push
	Endpoint     string            // 예: "http://loki:3100/loki/api/v1/push"
	TenantID     string            // multi-tenant Loki 사용 시 X-Scope-OrgID 등에 사용
	Username     string            // basic auth 사용자명(선택)
	Password     string            // basic auth 비밀번호(선택)
	StaticLabels map[string]string // 모든 로그에 공통으로 붙일 라벨 (app=hop-gate,env=dev 등)
}

// ServerConfig 는 서버 프로세스 설정을 담습니다.
type ServerConfig struct {
	HTTPListen   string   // 예: ":80"
	HTTPSListen  string   // 예: ":443"
	DTLSListen   string   // 예: ":443"
	Domain       string   // 메인 도메인
	ProxyDomains []string // 프록시 서브도메인 또는 별도 도메인
	Debug        bool     // true 이면 디버그 모드 (예: self-signed 인증서 신뢰, 검증 스킵 등)

	Logging LoggingConfig // 서버용 로그 설정
}

// ClientConfig 는 클라이언트 프로세스 설정을 담습니다.
// 현재 클라이언트는 다음 4가지 설정만 사용합니다.
//   - ServerAddr   : DTLS 서버 주소 (host:port)
//   - Domain       : 서버에서 등록된 도메인 (예: api.example.com)
//   - ClientAPIKey : 도메인에 매핑된 64자 클라이언트 API Key
//   - LocalTarget  : 로컬에서 요청할 서버 주소 (예: 127.0.0.1:8080)
//
// 값은 .env/환경변수와 CLI 인자를 조합해 구성하며,
// CLI 인자가 우선, env 가 후순위로 적용됩니다.
type ClientConfig struct {
	ServerAddr   string // DTLS 서버 주소 (host:port)
	Domain       string // 서버에서 등록된 도메인 (예: api.example.com)
	ClientAPIKey string // 도메인에 매핑된 64자 클라이언트 API Key
	LocalTarget  string // 로컬에서 요청할 서버 주소 (예: 127.0.0.1:8080)
	Debug        bool   // true 이면 디버그 모드 (예: 서버 인증서 검증 스킵 등)

	Logging LoggingConfig // 클라이언트용 로그 설정
}

var (
	dotenvOnce sync.Once
	dotenvErr  error
)

// loadDotEnvOnce 는 현재 작업 디렉터리의 .env 파일을 한 번만 읽어서 os.Environ 에 주입합니다.
// - KEY=VALUE, export KEY=VALUE 형식을 지원
// - # 으로 시작하는 줄은 주석으로 간주합니다.
func loadDotEnvOnce() {
	dotenvOnce.Do(func() {
		fi, err := os.Stat(".env")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// .env 가 없으면 조용히 무시
				return
			}
			dotenvErr = err
			return
		}
		if fi.IsDir() {
			// 디렉터리이면 무시
			return
		}

		f, err := os.Open(".env")
		if err != nil {
			dotenvErr = err
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "export ") {
				line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// 양 끝의 작은/큰따옴표 제거
			val = strings.Trim(val, `"'`)

			if key != "" {
				// 이미 OS 환경변수에 설정된 값이 있는 경우 이를 우선시하고,
				// 비어 있는 키에 대해서만 .env 값을 주입합니다.
				if _, exists := os.LookupEnv(key); !exists {
					_ = os.Setenv(key, val)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			dotenvErr = err
			return
		}
	})
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

func parseCSVEnv(key string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseKeyValueCSV 는 "k1=v1,k2=v2" 형태의 문자열을 map 으로 변환합니다.
func parseKeyValueCSV(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	m := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k != "" {
			m[k] = v
		}
	}
	return m
}

// parseServicePortsEnv 는 "name1=127.0.0.1:8080,name2=127.0.0.1:9000" 형식을 파싱합니다.
func parseServicePortsEnv(key string) map[string]string {
	raw := os.Getenv(key)
	return parseKeyValueCSV(raw)
}

// loadLoggingFromEnv 는 공통 로그 설정을 .env/환경변수에서 읽어옵니다.
func loadLoggingFromEnv() LoggingConfig {
	level := getEnvOrDefault("HOP_LOG_LEVEL", "info")

	lokiEnable := getEnvBool("HOP_LOKI_ENABLE", false)
	lokiEndpoint := os.Getenv("HOP_LOKI_ENDPOINT")
	lokiTenantID := os.Getenv("HOP_LOKI_TENANT_ID")
	lokiUsername := os.Getenv("HOP_LOKI_USERNAME")
	lokiPassword := os.Getenv("HOP_LOKI_PASSWORD")
	lokiStaticLabels := parseKeyValueCSV(os.Getenv("HOP_LOKI_STATIC_LABELS"))

	return LoggingConfig{
		Level: level,
		Loki: LokiConfig{
			Enable:       lokiEnable,
			Endpoint:     lokiEndpoint,
			TenantID:     lokiTenantID,
			Username:     lokiUsername,
			Password:     lokiPassword,
			StaticLabels: lokiStaticLabels,
		},
	}
}

// LoadServerConfigFromEnv 는 .env 를 한 번 읽어 현재 환경변수를 보완한 뒤
// "환경변수 > .env" 우선순위로 서버 설정을 구성합니다.
func LoadServerConfigFromEnv() (*ServerConfig, error) {
	loadDotEnvOnce()
	if dotenvErr != nil {
		return nil, dotenvErr
	}

	cfg := &ServerConfig{
		HTTPListen:   getEnvOrDefault("HOP_SERVER_HTTP_LISTEN", ":80"),
		HTTPSListen:  getEnvOrDefault("HOP_SERVER_HTTPS_LISTEN", ":443"),
		DTLSListen:   getEnvOrDefault("HOP_SERVER_DTLS_LISTEN", ":443"),
		Domain:       os.Getenv("HOP_SERVER_DOMAIN"),
		ProxyDomains: parseCSVEnv("HOP_SERVER_PROXY_DOMAINS"),
		Debug:        getEnvBool("HOP_SERVER_DEBUG", false),
		Logging:      loadLoggingFromEnv(),
	}
	return cfg, nil
}

// LoadClientConfigFromEnv 는 .env 를 한 번 읽어 현재 환경변수를 보완한 뒤
// "환경변수 > .env" 우선순위로 클라이언트 설정을 구성합니다.
// 실제 런타임에서 사용되는 필드는 ServerAddr, Domain, ClientAPIKey, LocalTarget 입니다.
func LoadClientConfigFromEnv() (*ClientConfig, error) {
	loadDotEnvOnce()
	if dotenvErr != nil {
		return nil, dotenvErr
	}

	cfg := &ClientConfig{
		ServerAddr:   os.Getenv("HOP_CLIENT_SERVER_ADDR"),
		Domain:       os.Getenv("HOP_CLIENT_DOMAIN"),
		ClientAPIKey: os.Getenv("HOP_CLIENT_API_KEY"),
		LocalTarget:  os.Getenv("HOP_CLIENT_LOCAL_TARGET"),
		Debug:        getEnvBool("HOP_CLIENT_DEBUG", false),
		Logging:      loadLoggingFromEnv(),
	}
	return cfg, nil
}

// Optional: 숫자 포트만 지정하고 싶을 경우를 위한 헬퍼 (예: "80" -> ":80").
// 현재는 사용하지 않지만, 향후 유효성 검사/정규화에 사용할 수 있습니다.
func normalizePort(p string, def string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return def
	}
	if strings.HasPrefix(p, ":") {
		return p
	}
	// 숫자로만 구성된 경우 ":" prefix 를 붙입니다.
	if _, err := strconv.Atoi(p); err == nil {
		return ":" + p
	}
	return p
}
