package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net"
	"os"
	"strings"

	"github.com/dalbodeule/hop-gate/internal/config"
	"github.com/dalbodeule/hop-gate/internal/dtls"
	"github.com/dalbodeule/hop-gate/internal/logging"
	"github.com/dalbodeule/hop-gate/internal/proxy"
)

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

// maskAPIKey 는 로그에 노출할 때 클라이언트 API Key 를 일부만 보여주기 위한 헬퍼입니다.
func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// firstNonEmpty 는 앞에서부터 처음으로 non-empty 인 문자열을 반환합니다.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func main() {
	logger := logging.NewStdJSONLogger("client")

	// 1. 환경변수(.env 포함)에서 클라이언트 설정 로드
	// internal/config 패키지가 .env 를 먼저 읽고, 이미 설정된 OS 환경변수를 우선시합니다.
	envCfg, err := config.LoadClientConfigFromEnv()
	if err != nil {
		logger.Error("failed to load client config from env", logging.Fields{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	// 2. 필수 환경 변수 유효성 검사 (.env 포함; OS 환경변수가 우선)
	serverAddrEnv := getEnvOrPanic(logger, "HOP_CLIENT_SERVER_ADDR")
	clientDomainEnv := getEnvOrPanic(logger, "HOP_CLIENT_DOMAIN")
	apiKeyEnv := getEnvOrPanic(logger, "HOP_CLIENT_API_KEY")
	localTargetEnv := getEnvOrPanic(logger, "HOP_CLIENT_LOCAL_TARGET")
	debugEnv := getEnvOrPanic(logger, "HOP_CLIENT_DEBUG")

	// 디버깅 플래그 형식 확인
	if debugEnv != "true" && debugEnv != "false" {
		logger.Error("invalid value for HOP_CLIENT_DEBUG; must be 'true' or 'false'", logging.Fields{
			"env":   "HOP_CLIENT_DEBUG",
			"value": debugEnv,
		})
		os.Exit(1)
	}

	// 유효성 검사 결과를 구조화 로그로 출력
	logger.Info("validated client env vars", logging.Fields{
		"HOP_CLIENT_SERVER_ADDR":  serverAddrEnv,
		"HOP_CLIENT_DOMAIN":       clientDomainEnv,
		"HOP_CLIENT_API_KEY_MASK": maskAPIKey(apiKeyEnv),
		"HOP_CLIENT_LOCAL_TARGET": localTargetEnv,
		"HOP_CLIENT_DEBUG":        debugEnv,
	})

	// CLI 인자 정의 (env 보다 우선 적용됨)
	serverAddrFlag := flag.String("server-addr", "", "DTLS server address (host:port)")
	domainFlag := flag.String("domain", "", "registered domain (e.g. api.example.com)")
	apiKeyFlag := flag.String("api-key", "", "client API key for the domain (64 chars)")
	localTargetFlag := flag.String("local-target", "", "local HTTP target (host:port), e.g. 127.0.0.1:8080")

	flag.Parse()

	// 2. CLI 인자 우선, env 후순위로 최종 설정 구성
	finalCfg := &config.ClientConfig{
		ServerAddr:   firstNonEmpty(strings.TrimSpace(*serverAddrFlag), strings.TrimSpace(envCfg.ServerAddr)),
		Domain:       firstNonEmpty(strings.TrimSpace(*domainFlag), strings.TrimSpace(envCfg.Domain)),
		ClientAPIKey: firstNonEmpty(strings.TrimSpace(*apiKeyFlag), strings.TrimSpace(envCfg.ClientAPIKey)),
		LocalTarget:  firstNonEmpty(strings.TrimSpace(*localTargetFlag), strings.TrimSpace(envCfg.LocalTarget)),
		Debug:        envCfg.Debug,
		Logging:      envCfg.Logging,
	}

	// 3. 필수 필드 검증
	missing := []string{}
	if finalCfg.ServerAddr == "" {
		missing = append(missing, "server_addr")
	}
	if finalCfg.Domain == "" {
		missing = append(missing, "domain")
	}
	if finalCfg.ClientAPIKey == "" {
		missing = append(missing, "api_key")
	}
	if finalCfg.LocalTarget == "" {
		missing = append(missing, "local_target")
	}

	if len(missing) > 0 {
		logger.Error("client config missing required fields", logging.Fields{
			"missing": missing,
		})
		os.Exit(1)
	}

	logger.Info("hop-gate client starting", logging.Fields{
		"stack":                 "prometheus-loki-grafana",
		"server_addr":           finalCfg.ServerAddr,
		"domain":                finalCfg.Domain,
		"local_target":          finalCfg.LocalTarget,
		"client_api_key_masked": maskAPIKey(finalCfg.ClientAPIKey),
		"debug":                 finalCfg.Debug,
	})

	// 4. DTLS 클라이언트 연결 및 핸드셰이크
	ctx := context.Background()

	// 디버그 모드에서는 서버 인증서 검증을 스킵(InsecureSkipVerify=true) 하여
	// self-signed 테스트 인증서도 신뢰하도록 합니다.
	// 운영 환경에서는 Debug=false 로 두고, 올바른 RootCAs / ServerName 을 갖는 tls.Config 를 사용해야 합니다.
	var tlsCfg *tls.Config
	if finalCfg.Debug {
		tlsCfg = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	} else {
		// 운영 모드: 시스템 루트 CA + SNI(ServerName)에 서버 도메인 설정
		rootCAs, err := x509.SystemCertPool()
		if err != nil || rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		tlsCfg = &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		}
	}
	// DTLS 서버 측은 SNI(ServerName)가 HOP_SERVER_DOMAIN(cfg.Domain)과 일치하는지 검사하므로,
	// 클라이언트 TLS 설정에도 반드시 도메인을 설정해준다.
	//
	// finalCfg.ServerAddr 가 "host:port" 형태이므로, SNI 에는 DNS(host) 부분만 넣어야 한다.
	host := finalCfg.ServerAddr
	if h, _, err := net.SplitHostPort(finalCfg.ServerAddr); err == nil && strings.TrimSpace(h) != "" {
		host = h
	}
	tlsCfg.ServerName = host

	client := dtls.NewPionClient(dtls.PionClientConfig{
		Addr:      finalCfg.ServerAddr,
		TLSConfig: tlsCfg,
	})

	sess, err := client.Connect()
	if err != nil {
		logger.Error("failed to establish dtls session", logging.Fields{
			"error": err.Error(),
		})
		os.Exit(1)
	}
	defer sess.Close()

	hsRes, err := dtls.PerformClientHandshake(ctx, sess, logger, finalCfg.Domain, finalCfg.ClientAPIKey, finalCfg.LocalTarget)
	if err != nil {
		logger.Error("dtls handshake failed", logging.Fields{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	logger.Info("dtls handshake completed", logging.Fields{
		"domain":       hsRes.Domain,
		"local_target": finalCfg.LocalTarget,
	})

	// 5. DTLS 세션 위에서 서버 요청을 처리하는 클라이언트 프록시 루프 시작
	clientProxy := proxy.NewClientProxy(logger, finalCfg.LocalTarget)
	logger.Info("starting client proxy loop", logging.Fields{
		"local_target": finalCfg.LocalTarget,
	})

	if err := clientProxy.StartLoop(ctx, sess); err != nil {
		logger.Error("client proxy loop exited with error", logging.Fields{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	logger.Info("client proxy loop exited normally", nil)
}
