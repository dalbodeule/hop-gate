package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/dalbodeule/hop-gate/internal/config"
	"github.com/dalbodeule/hop-gate/internal/logging"
	protocolpb "github.com/dalbodeule/hop-gate/internal/protocol/pb"
)

// version 은 빌드 시 -ldflags "-X main.version=xxxxxxx" 로 덮어쓰이는 필드입니다.
// 기본값 "dev" 는 로컬 개발용입니다.
var version = "dev"

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

// runGRPCTunnelClient 는 gRPC 기반 터널을 사용하는 실험적 클라이언트 진입점입니다. (ko)
// runGRPCTunnelClient is an experimental entrypoint for a gRPC-based tunnel client. (en)
func runGRPCTunnelClient(ctx context.Context, logger logging.Logger, finalCfg *config.ClientConfig) error {
	// TLS 설정은 기존 DTLS 클라이언트와 동일한 정책을 사용합니다. (ko)
	// TLS configuration mirrors the existing DTLS client policy. (en)
	var tlsCfg *tls.Config
	if finalCfg.Debug {
		tlsCfg = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	} else {
		rootCAs, err := x509.SystemCertPool()
		if err != nil || rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		tlsCfg = &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		}
	}

	// finalCfg.ServerAddr 가 "host:port" 형태이므로, SNI 에는 DNS(host) 부분만 넣어야 한다.
	host := finalCfg.ServerAddr
	if h, _, err := net.SplitHostPort(finalCfg.ServerAddr); err == nil && strings.TrimSpace(h) != "" {
		host = h
	}
	tlsCfg.ServerName = host

	creds := credentials.NewTLS(tlsCfg)

	log := logger.With(logging.Fields{
		"component":    "grpc_tunnel_client",
		"server_addr":  finalCfg.ServerAddr,
		"domain":       finalCfg.Domain,
		"local_target": finalCfg.LocalTarget,
	})

	log.Info("dialing grpc tunnel", nil)

	conn, err := grpc.DialContext(ctx, finalCfg.ServerAddr, grpc.WithTransportCredentials(creds), grpc.WithBlock())
	if err != nil {
		log.Error("failed to dial grpc tunnel server", logging.Fields{
			"error": err.Error(),
		})
		return err
	}
	defer conn.Close()

	client := protocolpb.NewHopGateTunnelClient(conn)

	stream, err := client.OpenTunnel(ctx)
	if err != nil {
		log.Error("failed to open grpc tunnel stream", logging.Fields{
			"error": err.Error(),
		})
		return err
	}

	log.Info("grpc tunnel stream opened", nil)

	// 초기 핸드셰이크: 도메인, API 키, 로컬 타깃 정보를 StreamOpen 헤더로 전송합니다. (ko)
	// Initial handshake: send domain, API key, and local target via StreamOpen headers. (en)
	headers := map[string]*protocolpb.HeaderValues{
		"X-HopGate-Domain":       {Values: []string{finalCfg.Domain}},
		"X-HopGate-API-Key":      {Values: []string{finalCfg.ClientAPIKey}},
		"X-HopGate-Local-Target": {Values: []string{finalCfg.LocalTarget}},
	}

	open := &protocolpb.StreamOpen{
		Id:          "control-0",
		ServiceName: "control",
		TargetAddr:  "",
		Header:      headers,
	}

	env := &protocolpb.Envelope{
		Payload: &protocolpb.Envelope_StreamOpen{
			StreamOpen: open,
		},
	}

	if err := stream.Send(env); err != nil {
		log.Error("failed to send initial stream_open handshake", logging.Fields{
			"error": err.Error(),
		})
		return err
	}

	log.Info("sent initial stream_open handshake on grpc tunnel", logging.Fields{
		"domain":       finalCfg.Domain,
		"local_target": finalCfg.LocalTarget,
		"api_key_mask": maskAPIKey(finalCfg.ClientAPIKey),
	})

	// 수신 루프: 현재는 수신된 Envelope 의 타입만 로그에 남기고 종료하지 않습니다. (ko)
	// Receive loop: currently only logs envelope payload types and keeps the tunnel open. (en)
	for {
		if ctx.Err() != nil {
			log.Info("context cancelled, closing grpc tunnel client", logging.Fields{
				"error": ctx.Err().Error(),
			})
			return ctx.Err()
		}

		in, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				log.Info("grpc tunnel stream closed by server", nil)
				return nil
			}
			log.Error("grpc tunnel receive error", logging.Fields{
				"error": err.Error(),
			})
			return err
		}

		payloadType := "unknown"
		switch in.Payload.(type) {
		case *protocolpb.Envelope_HttpRequest:
			payloadType = "http_request"
		case *protocolpb.Envelope_HttpResponse:
			payloadType = "http_response"
		case *protocolpb.Envelope_StreamOpen:
			payloadType = "stream_open"
		case *protocolpb.Envelope_StreamData:
			payloadType = "stream_data"
		case *protocolpb.Envelope_StreamClose:
			payloadType = "stream_close"
		case *protocolpb.Envelope_StreamAck:
			payloadType = "stream_ack"
		}

		log.Info("received envelope on grpc tunnel client", logging.Fields{
			"payload_type": payloadType,
		})

		// 이후 단계에서 여기서 HTTP 프록시와의 연동(요청/응답 처리)을 구현할 예정입니다. (ko)
		// Future 3.3 work will hook HTTP proxy logic here. (en)
	}
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
	serverAddrFlag := flag.String("server-addr", "", "HopGate server address (host:port)")
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
		"version":               version,
		"server_addr":           finalCfg.ServerAddr,
		"domain":                finalCfg.Domain,
		"local_target":          finalCfg.LocalTarget,
		"client_api_key_masked": maskAPIKey(finalCfg.ClientAPIKey),
		"debug":                 finalCfg.Debug,
	})

	ctx := context.Background()

	// 현재 클라이언트는 DTLS 레이어 없이 gRPC 터널만을 사용합니다. (ko)
	// The client now uses only the gRPC tunnel, without any DTLS layer. (en)
	if err := runGRPCTunnelClient(ctx, logger, finalCfg); err != nil {
		logger.Error("grpc tunnel client exited with error", logging.Fields{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	logger.Info("grpc tunnel client exited normally", nil)
}
