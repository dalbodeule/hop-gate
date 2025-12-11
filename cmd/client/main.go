package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/dalbodeule/hop-gate/internal/config"
	"github.com/dalbodeule/hop-gate/internal/logging"
	"github.com/dalbodeule/hop-gate/internal/protocol"
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

	// 로컬 HTTP 프록시용 HTTP 클라이언트 구성. (ko)
	// HTTP client used to forward requests to the local target. (en)
	httpClient := &http.Client{
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
	}

	// 서버→클라이언트 방향 StreamOpen/StreamData/StreamClose 를
	// HTTP 요청 단위로 모으기 위한 per-stream 상태 테이블입니다. (ko)
	// Per-stream state table to assemble HTTP requests from StreamOpen/Data/Close. (en)
	type inboundStream struct {
		open *protocolpb.StreamOpen
		body bytes.Buffer
	}

	streams := make(map[string]*inboundStream)
	var streamsMu sync.Mutex

	// gRPC 스트림에 대한 Send 는 동시 호출이 안전하지 않으므로, sendMu 로 직렬화합니다. (ko)
	// gRPC streaming Send is not safe for concurrent calls; protect with a mutex. (en)
	var sendMu sync.Mutex
	sendEnv := func(e *protocolpb.Envelope) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(e)
	}

	// 서버에서 전달된 StreamOpen/StreamData/StreamClose 를 로컬 HTTP 요청으로 변환하고,
	// 응답을 StreamOpen/StreamData/StreamClose 로 다시 서버에 전송하는 헬퍼입니다. (ko)
	// handleStream forwards a single logical HTTP request to the local target
	// and sends the response back as StreamOpen/StreamData/StreamClose frames. (en)
	handleStream := func(so *protocolpb.StreamOpen, body []byte) {
		go func() {
			streamID := strings.TrimSpace(so.Id)
			if streamID == "" {
				log.Error("inbound stream has empty id", logging.Fields{})
				return
			}

			if finalCfg.LocalTarget == "" {
				log.Error("local target is empty; cannot forward request", logging.Fields{
					"stream_id": streamID,
				})
				return
			}

			// Pseudo-headers 에서 메서드/URL/Host 추출. (ko)
			// Extract method/URL/host from pseudo-headers. (en)
			method := http.MethodGet
			if hv, ok := so.Header[protocol.HeaderKeyMethod]; ok && hv != nil && len(hv.Values) > 0 && strings.TrimSpace(hv.Values[0]) != "" {
				method = hv.Values[0]
			}
			urlStr := "/"
			if hv, ok := so.Header[protocol.HeaderKeyURL]; ok && hv != nil && len(hv.Values) > 0 && strings.TrimSpace(hv.Values[0]) != "" {
				urlStr = hv.Values[0]
			}

			u, err := url.Parse(urlStr)
			if err != nil {
				errMsg := fmt.Sprintf("parse url from stream_open: %v", err)
				log.Error("failed to parse url from stream_open", logging.Fields{
					"stream_id": streamID,
					"error":     err.Error(),
				})

				respHeader := map[string]*protocolpb.HeaderValues{
					"Content-Type": {
						Values: []string{"text/plain; charset=utf-8"},
					},
					protocol.HeaderKeyStatus: {
						Values: []string{strconv.Itoa(http.StatusBadGateway)},
					},
				}
				respOpen := &protocolpb.Envelope{
					Payload: &protocolpb.Envelope_StreamOpen{
						StreamOpen: &protocolpb.StreamOpen{
							Id:          streamID,
							ServiceName: so.ServiceName,
							TargetAddr:  so.TargetAddr,
							Header:      respHeader,
						},
					},
				}
				if err2 := sendEnv(respOpen); err2 != nil {
					log.Error("failed to send error stream_open from client", logging.Fields{
						"stream_id": streamID,
						"error":     err2.Error(),
					})
					return
				}

				dataEnv := &protocolpb.Envelope{
					Payload: &protocolpb.Envelope_StreamData{
						StreamData: &protocolpb.StreamData{
							Id:   streamID,
							Seq:  0,
							Data: []byte("HopGate client: " + errMsg),
						},
					},
				}
				if err2 := sendEnv(dataEnv); err2 != nil {
					log.Error("failed to send error stream_data from client", logging.Fields{
						"stream_id": streamID,
						"error":     err2.Error(),
					})
					return
				}

				closeEnv := &protocolpb.Envelope{
					Payload: &protocolpb.Envelope_StreamClose{
						StreamClose: &protocolpb.StreamClose{
							Id:    streamID,
							Error: errMsg,
						},
					},
				}
				if err2 := sendEnv(closeEnv); err2 != nil {
					log.Error("failed to send error stream_close from client", logging.Fields{
						"stream_id": streamID,
						"error":     err2.Error(),
					})
				}
				return
			}
			u.Scheme = "http"
			u.Host = finalCfg.LocalTarget

			// 로컬 HTTP 요청용 헤더 구성 (pseudo-headers 제거). (ko)
			// Build local HTTP headers, stripping pseudo-headers. (en)
			httpHeader := make(http.Header, len(so.Header))
			for k, hv := range so.Header {
				if k == protocol.HeaderKeyMethod ||
					k == protocol.HeaderKeyURL ||
					k == protocol.HeaderKeyHost ||
					k == protocol.HeaderKeyStatus {
					continue
				}
				if hv == nil {
					continue
				}
				for _, v := range hv.Values {
					httpHeader.Add(k, v)
				}
			}

			var reqBody io.Reader
			if len(body) > 0 {
				reqBody = bytes.NewReader(body)
			}

			req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
			if err != nil {
				errMsg := fmt.Sprintf("create http request from stream: %v", err)
				log.Error("failed to create local http request", logging.Fields{
					"stream_id": streamID,
					"error":     err.Error(),
				})

				respHeader := map[string]*protocolpb.HeaderValues{
					"Content-Type": {
						Values: []string{"text/plain; charset=utf-8"},
					},
					protocol.HeaderKeyStatus: {
						Values: []string{strconv.Itoa(http.StatusBadGateway)},
					},
				}
				respOpen := &protocolpb.Envelope{
					Payload: &protocolpb.Envelope_StreamOpen{
						StreamOpen: &protocolpb.StreamOpen{
							Id:          streamID,
							ServiceName: so.ServiceName,
							TargetAddr:  so.TargetAddr,
							Header:      respHeader,
						},
					},
				}
				if err2 := sendEnv(respOpen); err2 != nil {
					log.Error("failed to send error stream_open from client", logging.Fields{
						"stream_id": streamID,
						"error":     err2.Error(),
					})
					return
				}

				dataEnv := &protocolpb.Envelope{
					Payload: &protocolpb.Envelope_StreamData{
						StreamData: &protocolpb.StreamData{
							Id:   streamID,
							Seq:  0,
							Data: []byte("HopGate client: " + errMsg),
						},
					},
				}
				if err2 := sendEnv(dataEnv); err2 != nil {
					log.Error("failed to send error stream_data from client", logging.Fields{
						"stream_id": streamID,
						"error":     err2.Error(),
					})
					return
				}

				closeEnv := &protocolpb.Envelope{
					Payload: &protocolpb.Envelope_StreamClose{
						StreamClose: &protocolpb.StreamClose{
							Id:    streamID,
							Error: errMsg,
						},
					},
				}
				if err2 := sendEnv(closeEnv); err2 != nil {
					log.Error("failed to send error stream_close from client", logging.Fields{
						"stream_id": streamID,
						"error":     err2.Error(),
					})
				}
				return
			}
			req.Header = httpHeader
			if len(body) > 0 {
				req.ContentLength = int64(len(body))
			}

			start := time.Now()
			logReq := log.With(logging.Fields{
				"component":    "grpc_client_proxy",
				"stream_id":    streamID,
				"service":      so.ServiceName,
				"method":       method,
				"url":          urlStr,
				"local_target": finalCfg.LocalTarget,
			})
			logReq.Info("forwarding stream http request to local target", nil)

			res, err := httpClient.Do(req)
			if err != nil {
				errMsg := fmt.Sprintf("perform local http request: %v", err)
				logReq.Error("local http request failed", logging.Fields{
					"error": err.Error(),
				})

				respHeader := map[string]*protocolpb.HeaderValues{
					"Content-Type": {
						Values: []string{"text/plain; charset=utf-8"},
					},
					protocol.HeaderKeyStatus: {
						Values: []string{strconv.Itoa(http.StatusBadGateway)},
					},
				}
				respOpen := &protocolpb.Envelope{
					Payload: &protocolpb.Envelope_StreamOpen{
						StreamOpen: &protocolpb.StreamOpen{
							Id:          streamID,
							ServiceName: so.ServiceName,
							TargetAddr:  so.TargetAddr,
							Header:      respHeader,
						},
					},
				}
				if err2 := sendEnv(respOpen); err2 != nil {
					logReq.Error("failed to send error stream_open from client", logging.Fields{
						"error": err2.Error(),
					})
					return
				}

				dataEnv := &protocolpb.Envelope{
					Payload: &protocolpb.Envelope_StreamData{
						StreamData: &protocolpb.StreamData{
							Id:   streamID,
							Seq:  0,
							Data: []byte("HopGate client: " + errMsg),
						},
					},
				}
				if err2 := sendEnv(dataEnv); err2 != nil {
					logReq.Error("failed to send error stream_data from client", logging.Fields{
						"error": err2.Error(),
					})
					return
				}

				closeEnv := &protocolpb.Envelope{
					Payload: &protocolpb.Envelope_StreamClose{
						StreamClose: &protocolpb.StreamClose{
							Id:    streamID,
							Error: errMsg,
						},
					},
				}
				if err2 := sendEnv(closeEnv); err2 != nil {
					logReq.Error("failed to send error stream_close from client", logging.Fields{
						"error": err2.Error(),
					})
				}
				return
			}
			defer res.Body.Close()

			// 응답 헤더 맵을 복사하고 상태 코드를 pseudo-header 로 추가합니다. (ko)
			// Copy response headers and attach status code as a pseudo-header. (en)
			respHeader := make(map[string]*protocolpb.HeaderValues, len(res.Header)+1)
			for k, vs := range res.Header {
				hv := &protocolpb.HeaderValues{
					Values: append([]string(nil), vs...),
				}
				respHeader[k] = hv
			}
			statusCode := res.StatusCode
			if statusCode == 0 {
				statusCode = http.StatusOK
			}
			respHeader[protocol.HeaderKeyStatus] = &protocolpb.HeaderValues{
				Values: []string{strconv.Itoa(statusCode)},
			}

			respOpen := &protocolpb.Envelope{
				Payload: &protocolpb.Envelope_StreamOpen{
					StreamOpen: &protocolpb.StreamOpen{
						Id:          streamID,
						ServiceName: so.ServiceName,
						TargetAddr:  so.TargetAddr,
						Header:      respHeader,
					},
				},
			}
			if err := sendEnv(respOpen); err != nil {
				logReq.Error("failed to send stream response open envelope from client", logging.Fields{
					"error": err.Error(),
				})
				return
			}

			// 응답 바디를 4KiB(StreamChunkSize) 단위로 잘라 StreamData 프레임으로 전송합니다. (ko)
			// Chunk the response body into 4KiB (StreamChunkSize) StreamData frames. (en)
			buf := make([]byte, protocol.StreamChunkSize)
			var seq uint64
			for {
				n, err := res.Body.Read(buf)
				if n > 0 {
					dataCopy := append([]byte(nil), buf[:n]...)
					dataEnv := &protocolpb.Envelope{
						Payload: &protocolpb.Envelope_StreamData{
							StreamData: &protocolpb.StreamData{
								Id:   streamID,
								Seq:  seq,
								Data: dataCopy,
							},
						},
					}
					if err2 := sendEnv(dataEnv); err2 != nil {
						logReq.Error("failed to send stream response data envelope from client", logging.Fields{
							"error": err2.Error(),
						})
						return
					}
					seq++
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					logReq.Error("failed to read local http response body", logging.Fields{
						"error": err.Error(),
					})
					break
				}
			}

			closeEnv := &protocolpb.Envelope{
				Payload: &protocolpb.Envelope_StreamClose{
					StreamClose: &protocolpb.StreamClose{
						Id:    streamID,
						Error: "",
					},
				},
			}
			if err := sendEnv(closeEnv); err != nil {
				logReq.Error("failed to send stream response close envelope from client", logging.Fields{
					"error": err.Error(),
				})
				return
			}

			logReq.Info("stream http response sent from client", logging.Fields{
				"status":     statusCode,
				"elapsed_ms": time.Since(start).Milliseconds(),
				"error":      "",
			})
		}()
	}

	// 수신 루프: 서버에서 들어오는 StreamOpen/StreamData/StreamClose 를
	// 로컬 HTTP 요청으로 변환하고 응답을 다시 터널로 전송합니다. (ko)
	// Receive loop: convert incoming StreamOpen/StreamData/StreamClose into local
	// HTTP requests and send responses back over the tunnel. (en)
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
		switch payload := in.Payload.(type) {
		case *protocolpb.Envelope_HttpRequest:
			payloadType = "http_request"
		case *protocolpb.Envelope_HttpResponse:
			payloadType = "http_response"
		case *protocolpb.Envelope_StreamOpen:
			payloadType = "stream_open"

			so := payload.StreamOpen
			if so == nil {
				log.Error("received stream_open with nil payload on grpc tunnel client", logging.Fields{})
				continue
			}
			streamID := strings.TrimSpace(so.Id)
			if streamID == "" {
				log.Error("received stream_open with empty stream id on grpc tunnel client", logging.Fields{})
				continue
			}

			streamsMu.Lock()
			if _, exists := streams[streamID]; exists {
				log.Error("received duplicate stream_open for existing stream on grpc tunnel client", logging.Fields{
					"stream_id": streamID,
				})
				streamsMu.Unlock()
				continue
			}
			streams[streamID] = &inboundStream{open: so}
			streamsMu.Unlock()

		case *protocolpb.Envelope_StreamData:
			payloadType = "stream_data"

			sd := payload.StreamData
			if sd == nil {
				log.Error("received stream_data with nil payload on grpc tunnel client", logging.Fields{})
				continue
			}
			streamID := strings.TrimSpace(sd.Id)
			if streamID == "" {
				log.Error("received stream_data with empty stream id on grpc tunnel client", logging.Fields{})
				continue
			}

			streamsMu.Lock()
			st := streams[streamID]
			streamsMu.Unlock()
			if st == nil {
				log.Warn("received stream_data for unknown stream on grpc tunnel client", logging.Fields{
					"stream_id": streamID,
				})
				continue
			}
			if len(sd.Data) > 0 {
				if _, err := st.body.Write(sd.Data); err != nil {
					log.Error("failed to buffer stream_data body on grpc tunnel client", logging.Fields{
						"stream_id": streamID,
						"error":     err.Error(),
					})
				}
			}

		case *protocolpb.Envelope_StreamClose:
			payloadType = "stream_close"

			sc := payload.StreamClose
			if sc == nil {
				log.Error("received stream_close with nil payload on grpc tunnel client", logging.Fields{})
				continue
			}
			streamID := strings.TrimSpace(sc.Id)
			if streamID == "" {
				log.Error("received stream_close with empty stream id on grpc tunnel client", logging.Fields{})
				continue
			}

			streamsMu.Lock()
			st := streams[streamID]
			if st != nil {
				delete(streams, streamID)
			}
			streamsMu.Unlock()
			if st == nil {
				log.Warn("received stream_close for unknown stream on grpc tunnel client", logging.Fields{
					"stream_id": streamID,
				})
				continue
			}

			// 현재까지 수신한 메타데이터/바디를 사용해 로컬 HTTP 요청을 수행하고,
			// 응답을 다시 터널로 전송합니다. (ko)
			// Use the accumulated metadata/body to perform the local HTTP request and
			// send the response back over the tunnel. (en)
			bodyCopy := append([]byte(nil), st.body.Bytes()...)
			handleStream(st.open, bodyCopy)

		case *protocolpb.Envelope_StreamAck:
			payloadType = "stream_ack"
			// 현재 gRPC 터널에서는 StreamAck 를 사용하지 않습니다. (ko)
			// StreamAck is currently unused for gRPC tunnels. (en)

		default:
			payloadType = fmt.Sprintf("unknown(%T)", in.Payload)
		}

		log.Info("received envelope on grpc tunnel client", logging.Fields{
			"payload_type": payloadType,
		})
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
