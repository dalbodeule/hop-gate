package main

import (
	"context"
	"crypto/tls"
	"os"

	"github.com/dalbodeule/hop-gate/internal/config"
	"github.com/dalbodeule/hop-gate/internal/dtls"
	"github.com/dalbodeule/hop-gate/internal/logging"
)

func main() {
	logger := logging.NewStdJSONLogger("server")

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

	// 2. DTLS 서버 리스너 생성 (pion/dtls 기반)
	//
	// Debug 모드일 때는 self-signed localhost 인증서를 사용해 테스트 할 수 있도록
	// internal/dtls.NewSelfSignedLocalhostConfig() 를 사용합니다.
	// 운영 환경에서는 internal/acme.Manager 를 통해 얻은 tls.Config 를
	// PionServerConfig.TLSConfig 로 전달해야 합니다.
	var tlsCfg *tls.Config
	if cfg.Debug {
		tlsCfg, err = dtls.NewSelfSignedLocalhostConfig()
		if err != nil {
			logger.Error("failed to create self-signed localhost cert", logging.Fields{
				"error": err.Error(),
			})
			os.Exit(1)
		}
		logger.Warn("using self-signed localhost certificate for DTLS (debug mode)", logging.Fields{
			"note": "do not use this in production",
		})
	}

	dtlsServer, err := dtls.NewPionServer(dtls.PionServerConfig{
		Addr:      cfg.DTLSListen,
		TLSConfig: tlsCfg, // debug 모드면 self-signed, 아니면 nil(기본값/ACME로 교체 예정)
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

	// 3. 도메인 검증기 준비 (현재는 Dummy 구현)
	//
	// DomainValidator 는 (domain, client_api_key) 조합을 검증합니다.
	// 지금은 DummyDomainValidator 로 모두 허용하지만,
	// 향후 ent + PostgreSQL 기반 구현으로 교체해야 합니다.
	validator := dtls.DummyDomainValidator{
		Logger: logger,
	}

	ctx := context.Background()

	// 4. DTLS Accept 루프 + Handshake
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
			defer s.Close()

			hsRes, err := dtls.PerformServerHandshake(ctx, s, validator, logger)
			if err != nil {
				// PerformServerHandshake 내부에서 이미 상세 로그를 남기므로 여기서는 요약만 기록합니다.
				logger.Warn("dtls handshake failed", logging.Fields{
					"session_id": s.ID(),
					"error":      err.Error(),
				})
				return
			}

			// Handshake 성공: 서버 측은 어떤 도메인이 연결되었는지 알 수 있습니다.
			logger.Info("dtls handshake completed", logging.Fields{
				"session_id": s.ID(),
				"domain":     hsRes.Domain,
			})

			// TODO:
			//   - hsRes.Domain 과 연결된 세션을 proxy 레이어에 등록
			//   - HTTP 요청을 이 세션을 통해 해당 클라이언트로 라우팅
			//   - 세션 생명주기/타임아웃 관리 등
		}(sess)
	}
}
