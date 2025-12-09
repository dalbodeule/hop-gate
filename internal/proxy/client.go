package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/dalbodeule/hop-gate/internal/dtls"
	"github.com/dalbodeule/hop-gate/internal/logging"
	"github.com/dalbodeule/hop-gate/internal/protocol"
)

// ClientProxy 는 서버로부터 받은 요청을 로컬 HTTP 서비스로 전달하는 클라이언트 측 프록시입니다. (ko)
// ClientProxy forwards requests from the server to local HTTP services. (en)
type ClientProxy struct {
	HTTPClient  *http.Client
	Logger      logging.Logger
	LocalTarget string // e.g. "127.0.0.1:8080"

	sendersMu     sync.Mutex
	streamSenders map[protocol.StreamID]*streamSender
}

// NewClientProxy 는 기본 HTTP 클라이언트 및 로거를 사용해 ClientProxy 를 생성합니다. (ko)
// NewClientProxy creates a ClientProxy with a default HTTP client and logger. (en)
func NewClientProxy(logger logging.Logger, localTarget string) *ClientProxy {
	if logger == nil {
		logger = logging.NewStdJSONLogger("client_proxy")
	}
	return &ClientProxy{
		HTTPClient: &http.Client{
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
		},
		Logger:        logger.With(logging.Fields{"component": "client_proxy"}),
		LocalTarget:   localTarget,
		streamSenders: make(map[protocol.StreamID]*streamSender),
	}
}

// StartLoop 는 DTLS 세션에서 protocol.Envelope 를 읽고, HTTP/스트림 요청의 경우 로컬 HTTP 요청을 수행한 뒤
// protocol.Envelope(HTTP/스트림 응답 포함)을 다시 세션으로 쓰는 루프를 실행합니다. (ko)
// StartLoop reads protocol.Envelope messages from the DTLS session; for HTTP/stream
// messages it performs local HTTP requests and writes back responses over the DTLS
// tunnel. (en)
type streamSender struct {
	mu          sync.Mutex
	outstanding map[uint64][]byte
}

func newStreamSender() *streamSender {
	return &streamSender{
		outstanding: make(map[uint64][]byte),
	}
}

func (s *streamSender) register(seq uint64, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.outstanding == nil {
		s.outstanding = make(map[uint64][]byte)
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	s.outstanding[seq] = buf
}

func (s *streamSender) handleAck(ack *protocol.StreamAck) map[uint64][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.outstanding == nil {
		return nil
	}

	// 연속 수신 완료 구간(seq <= AckSeq)은 outstanding 에서 제거합니다.
	for seq := range s.outstanding {
		if seq <= ack.AckSeq {
			delete(s.outstanding, seq)
		}
	}

	// LostSeqs 가 비어 있으면 재전송할 것이 없습니다.
	if len(ack.LostSeqs) == 0 {
		return nil
	}

	// LostSeqs 에 포함된 시퀀스 중, 아직 outstanding 에 남아 있는 것들만 재전송 대상으로 선택합니다.
	lost := make(map[uint64][]byte, len(ack.LostSeqs))
	for _, seq := range ack.LostSeqs {
		if data, ok := s.outstanding[seq]; ok {
			buf := make([]byte, len(data))
			copy(buf, data)
			lost[seq] = buf
		}
	}
	return lost
}

func (p *ClientProxy) registerStreamSender(id protocol.StreamID, sender *streamSender) {
	p.sendersMu.Lock()
	defer p.sendersMu.Unlock()
	if p.streamSenders == nil {
		p.streamSenders = make(map[protocol.StreamID]*streamSender)
	}
	p.streamSenders[id] = sender
}

func (p *ClientProxy) unregisterStreamSender(id protocol.StreamID) {
	p.sendersMu.Lock()
	defer p.sendersMu.Unlock()
	if p.streamSenders == nil {
		return
	}
	delete(p.streamSenders, id)
}

func (p *ClientProxy) getStreamSender(id protocol.StreamID) *streamSender {
	p.sendersMu.Lock()
	defer p.sendersMu.Unlock()
	if p.streamSenders == nil {
		return nil
	}
	return p.streamSenders[id]
}

func (p *ClientProxy) StartLoop(ctx context.Context, sess dtls.Session) error {
	if ctx == nil {
		ctx = context.Background()
	}
	log := p.Logger

	// NOTE: pion/dtls 는 복호화된 애플리케이션 데이터를 호출자가 제공한 버퍼에 채워 넣습니다.
	// DTLS는 UDP 기반이므로 한 번의 Read()에서 전체 datagram을 읽어야 하며,
	// pion/dtls 내부 버퍼 한계(8KB)를 초과하는 메시지는 "dtls: buffer too small" 오류를 발생시킵니다.
	// 이를 방지하기 위해 DTLS 세션을 bufio.Reader로 감싸서 datagram을 완전히 읽어들인 후 파싱합니다. (ko)
	// NOTE: pion/dtls decrypts application data into the buffer provided by the caller.
	// Since DTLS is UDP-based, the entire datagram must be read in a single Read() call,
	// and messages exceeding pion/dtls's internal buffer limit (8KB) will trigger
	// "dtls: buffer too small" errors. To prevent this, we wrap the DTLS session with
	// a bufio.Reader to fully read the datagram before parsing. (en)
	codec := protocol.DefaultCodec
	bufferedReader := bufio.NewReaderSize(sess, protocol.GetDTLSReadBufferSize())

	for {
		select {
		case <-ctx.Done():
			log.Info("client proxy loop stopping due to context cancellation", logging.Fields{
				"reason": ctx.Err().Error(),
			})
			return nil
		default:
		}

		var env protocol.Envelope
		if err := codec.Decode(bufferedReader, &env); err != nil {
			if err == io.EOF {
				log.Info("dtls session closed by server", nil)
				return nil
			}
			log.Error("failed to decode protocol envelope", logging.Fields{
				"error": err.Error(),
			})
			return err
		}

		switch env.Type {
		case protocol.MessageTypeHTTP:
			if err := p.handleHTTPEnvelope(ctx, sess, &env); err != nil {
				log.Error("failed to handle http envelope", logging.Fields{
					"error": err.Error(),
				})
				return err
			}
		case protocol.MessageTypeStreamOpen:
			if err := p.handleStreamRequest(ctx, sess, bufferedReader, &env); err != nil {
				log.Error("failed to handle stream http envelope", logging.Fields{
					"error": err.Error(),
				})
				return err
			}
		case protocol.MessageTypeStreamAck:
			sa := env.StreamAck
			if sa == nil {
				log.Error("received stream_ack envelope with nil payload", nil)
				return fmt.Errorf("stream_ack payload is nil")
			}
			streamID := protocol.StreamID(sa.ID)
			sender := p.getStreamSender(streamID)
			if sender == nil {
				log.Warn("received stream_ack for unknown stream", logging.Fields{
					"stream_id": sa.ID,
				})
				continue
			}
			lost := sender.handleAck(sa)
			// LostSeqs 를 기반으로 선택적 재전송 수행
			for seq, data := range lost {
				retryEnv := protocol.Envelope{
					Type: protocol.MessageTypeStreamData,
					StreamData: &protocol.StreamData{
						ID:   streamID,
						Seq:  seq,
						Data: data,
					},
				}
				if err := codec.Encode(sess, &retryEnv); err != nil {
					log.Error("failed to retransmit stream_data after stream_ack", logging.Fields{
						"stream_id": streamID,
						"seq":       seq,
						"error":     err.Error(),
					})
					return err
				}
				log.Info("retransmitted stream_data after stream_ack", logging.Fields{
					"stream_id": streamID,
					"seq":       seq,
				})
			}
		case protocol.MessageTypeStreamData:
			// StreamData received at top level (not expected, should be consumed by handleStreamRequest)
			// This can happen if frames arrive out of order or if there's a protocol mismatch
			streamID := "unknown"
			if env.StreamData != nil {
				streamID = string(env.StreamData.ID)
			}
			log.Warn("received unexpected stream_data at top level, ignoring", logging.Fields{
				"stream_id": streamID,
			})
			continue
		case protocol.MessageTypeStreamClose:
			// StreamClose received at top level (not expected, should be consumed by handleStreamRequest)
			// This can happen if frames arrive out of order or if there's a protocol mismatch
			streamID := "unknown"
			if env.StreamClose != nil {
				streamID = string(env.StreamClose.ID)
			}
			log.Warn("received unexpected stream_close at top level, ignoring", logging.Fields{
				"stream_id": streamID,
			})
			continue
		default:
			log.Error("received unsupported envelope type from server", logging.Fields{
				"type": env.Type,
			})
			return fmt.Errorf("unsupported envelope type %q", env.Type)
		}
	}
}

// handleHTTPEnvelope 는 기존 단일 HTTP 요청/응답 Envelope 경로를 처리합니다. (ko)
// handleHTTPEnvelope handles the legacy single HTTP request/response envelope path. (en)
func (p *ClientProxy) handleHTTPEnvelope(ctx context.Context, sess dtls.Session, env *protocol.Envelope) error {
	if env.HTTPRequest == nil {
		return fmt.Errorf("http envelope missing http_request payload")
	}

	req := env.HTTPRequest
	log := p.Logger
	start := time.Now()

	logReq := log.With(logging.Fields{
		"request_id":   req.RequestID,
		"service":      req.ServiceName,
		"method":       req.Method,
		"url":          req.URL,
		"client_id":    req.ClientID,
		"local_target": p.LocalTarget,
	})
	logReq.Info("received http envelope from server", nil)

	resp := protocol.Response{
		RequestID: req.RequestID,
		Header:    make(map[string][]string),
	}

	// 로컬 HTTP 요청 수행
	if err := p.forwardToLocal(ctx, req, &resp); err != nil {
		resp.Status = http.StatusBadGateway
		resp.Error = err.Error()
		logReq.Error("local http request failed", logging.Fields{
			"error": err.Error(),
		})
	}

	// HTTP 응답을 Envelope 로 감싸서 서버로 전송합니다.
	respEnv := protocol.Envelope{
		Type:         protocol.MessageTypeHTTP,
		HTTPResponse: &resp,
	}

	if err := protocol.DefaultCodec.Encode(sess, &respEnv); err != nil {
		logReq.Error("failed to encode http response envelope", logging.Fields{
			"error": err.Error(),
		})
		return err
	}

	logReq.Info("http response envelope sent to server", logging.Fields{
		"status":     resp.Status,
		"elapsed_ms": time.Since(start).Milliseconds(),
		"error":      resp.Error,
	})

	return nil
}

// handleStreamRequest 는 StreamOpen/StreamData/StreamClose 기반 HTTP 요청/응답 스트림을 처리합니다. (ko)
// handleStreamRequest handles an HTTP request/response exchange using StreamOpen/StreamData/StreamClose frames. (en)
func (p *ClientProxy) handleStreamRequest(ctx context.Context, sess dtls.Session, reader io.Reader, openEnv *protocol.Envelope) error {
	codec := protocol.DefaultCodec
	log := p.Logger

	so := openEnv.StreamOpen
	if so == nil {
		return fmt.Errorf("stream_open envelope missing payload")
	}

	streamID := so.ID
	// 이 스트림에 대한 송신 측 ARQ 상태를 준비하고, StartLoop 에서 들어오는 StreamAck 와 연동합니다.
	sender := newStreamSender()
	p.registerStreamSender(streamID, sender)
	defer p.unregisterStreamSender(streamID)

	// Pseudo-header 에서 HTTP 메타데이터를 추출합니다. (ko)
	// Extract HTTP metadata from pseudo-headers. (en)
	method := firstHeaderValue(so.Header, protocol.HeaderKeyMethod, http.MethodGet)
	urlStr := firstHeaderValue(so.Header, protocol.HeaderKeyURL, "/")
	_ = firstHeaderValue(so.Header, protocol.HeaderKeyHost, "")

	if p.LocalTarget == "" {
		return fmt.Errorf("local target is empty")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("parse url from stream_open: %w", err)
	}
	u.Scheme = "http"
	u.Host = p.LocalTarget

	// 로컬 HTTP 요청용 헤더 맵을 생성하면서 pseudo-header 는 제거합니다. (ko)
	// Build local HTTP header map while stripping pseudo-headers. (en)
	httpHeader := make(http.Header, len(so.Header))
	for k, vs := range so.Header {
		if k == protocol.HeaderKeyMethod ||
			k == protocol.HeaderKeyURL ||
			k == protocol.HeaderKeyHost ||
			k == protocol.HeaderKeyStatus {
			continue
		}
		for _, v := range vs {
			httpHeader.Add(k, v)
		}
	}

	// 요청 바디를 StreamData/StreamClose 프레임에서 모두 읽어 메모리에 적재합니다. (ko)
	// Read the entire request body from StreamData/StreamClose frames into memory. (en)
	//
	// 동시에 수신 측 ARQ 상태( expectedSeq / out-of-order 버퍼 / LostSeqs )를 관리하고
	// StreamAck 를 전송해 선택적 재전송(Selective Retransmission)을 유도합니다.
	var (
		bodyBuf     bytes.Buffer
		expectedSeq uint64
		received    = make(map[uint64][]byte)
		lost        = make(map[uint64]struct{})
	)
	const maxLostReport = 32

	for {
		var env protocol.Envelope
		if err := codec.Decode(reader, &env); err != nil {
			if err == io.EOF {
				return fmt.Errorf("unexpected EOF while reading stream request body")
			}
			return fmt.Errorf("decode stream request frame: %w", err)
		}

		switch env.Type {
		case protocol.MessageTypeStreamData:
			sd := env.StreamData
			if sd == nil {
				return fmt.Errorf("stream_data payload is nil")
			}
			if sd.ID != streamID {
				return fmt.Errorf("stream_data for unexpected stream id %q (expected %q)", sd.ID, streamID)
			}

			// 수신 측 ARQ: Seq 에 따라 분기
			switch {
			case sd.Seq == expectedSeq:
				// 기대하던 순서의 프레임: 바로 bodyBuf 에 기록하고, 이후 버퍼된 연속 프레임도 flush.
				if len(sd.Data) > 0 {
					if _, err := bodyBuf.Write(sd.Data); err != nil {
						return fmt.Errorf("buffer stream_data: %w", err)
					}
				}
				expectedSeq++
				for {
					data, ok := received[expectedSeq]
					if !ok {
						break
					}
					if len(data) > 0 {
						if _, err := bodyBuf.Write(data); err != nil {
							return fmt.Errorf("buffer reordered stream_data: %w", err)
						}
					}
					delete(received, expectedSeq)
					delete(lost, expectedSeq)
					expectedSeq++
				}

				// AckSeq 이전 구간의 lost 항목 정리
				for seq := range lost {
					if seq < expectedSeq {
						delete(lost, seq)
					}
				}

			case sd.Seq > expectedSeq:
				// 앞선 일부 Seq 들이 누락된 상태: 현재 프레임을 버퍼링하고 missing seq 들을 lost 에 추가.
				if len(sd.Data) > 0 {
					buf := make([]byte, len(sd.Data))
					copy(buf, sd.Data)
					received[sd.Seq] = buf
				}
				for seq := expectedSeq; seq < sd.Seq && len(lost) < maxLostReport; seq++ {
					if _, ok := lost[seq]; !ok {
						lost[seq] = struct{}{}
					}
				}

			default:
				// sd.Seq < expectedSeq 인 경우: 이미 처리했거나 Ack 로 커버된 프레임 → 무시.
			}

			// 수신 측 StreamAck 전송:
			//   - AckSeq: 0부터 시작해 연속으로 수신 완료한 마지막 시퀀스 (expectedSeq-1)
			//   - LostSeqs: 현재 윈도우 내에서 누락된 시퀀스 중 상한 개수(maxLostReport)까지만 포함
			var ackSeq uint64
			if expectedSeq == 0 {
				ackSeq = 0
			} else {
				ackSeq = expectedSeq - 1
			}

			lostSeqs := make([]uint64, 0, len(lost))
			for seq := range lost {
				if seq >= expectedSeq {
					lostSeqs = append(lostSeqs, seq)
				}
			}
			if len(lostSeqs) > 0 {
				sort.Slice(lostSeqs, func(i, j int) bool { return lostSeqs[i] < lostSeqs[j] })
				if len(lostSeqs) > maxLostReport {
					lostSeqs = lostSeqs[:maxLostReport]
				}
			}

			ackEnv := protocol.Envelope{
				Type: protocol.MessageTypeStreamAck,
				StreamAck: &protocol.StreamAck{
					ID:       streamID,
					AckSeq:   ackSeq,
					LostSeqs: lostSeqs,
				},
			}
			if err := codec.Encode(sess, &ackEnv); err != nil {
				return fmt.Errorf("send stream ack: %w", err)
			}

		case protocol.MessageTypeStreamClose:
			sc := env.StreamClose
			if sc == nil {
				return fmt.Errorf("stream_close payload is nil")
			}
			if sc.ID != streamID {
				return fmt.Errorf("stream_close for unexpected stream id %q (expected %q)", sc.ID, streamID)
			}
			// sc.Error 는 최소 구현에서는 로컬 요청 에러와 별도로 취급하지 않습니다. (ko)
			// For the minimal implementation we do not surface sc.Error here. (en)
			goto haveBody
		default:
			return fmt.Errorf("unexpected envelope type %q while reading stream request body", env.Type)
		}
	}

haveBody:
	bodyBytes := bodyBuf.Bytes()

	// 로컬 HTTP 요청 생성 (stream 기반 요청을 실제 HTTP 요청으로 변환). (ko)
	// Build the local HTTP request from the stream-based metadata and body. (en)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create http request from stream: %w", err)
	}
	if len(bodyBytes) > 0 {
		buf := bytes.NewReader(bodyBytes)
		req.Body = io.NopCloser(buf)
		req.ContentLength = int64(len(bodyBytes))
	}
	req.Header = httpHeader

	start := time.Now()
	logReq := log.With(logging.Fields{
		"request_id":   string(streamID),
		"service":      so.Service,
		"method":       method,
		"url":          urlStr,
		"stream_id":    string(streamID),
		"local_target": p.LocalTarget,
	})
	logReq.Info("received stream_open envelope from server", nil)

	res, err := p.HTTPClient.Do(req)
	if err != nil {
		// 로컬 요청 실패 시, 502 + 에러 메시지를 스트림 응답으로 전송합니다. (ko)
		// On local request failure, send a 502 response over the stream. (en)
		errMsg := fmt.Sprintf("perform http request: %v", err)
		streamRespHeader := map[string][]string{
			"Content-Type":           {"text/plain; charset=utf-8"},
			protocol.HeaderKeyStatus: {strconv.Itoa(http.StatusBadGateway)},
		}
		respOpen := protocol.Envelope{
			Type: protocol.MessageTypeStreamOpen,
			StreamOpen: &protocol.StreamOpen{
				ID:         streamID,
				Service:    so.Service,
				TargetAddr: so.TargetAddr,
				Header:     streamRespHeader,
			},
		}
		if err2 := codec.Encode(sess, &respOpen); err2 != nil {
			logReq.Error("failed to encode stream response open envelope (error path)", logging.Fields{
				"error": err2.Error(),
			})
			return err2
		}

		dataEnv := protocol.Envelope{
			Type: protocol.MessageTypeStreamData,
			StreamData: &protocol.StreamData{
				ID:   streamID,
				Seq:  0,
				Data: []byte("HopGate: " + errMsg),
			},
		}
		// 에러 응답 프레임도 ARQ 대상에 등록합니다.
		sender.register(0, dataEnv.StreamData.Data)
		if err2 := codec.Encode(sess, &dataEnv); err2 != nil {
			logReq.Error("failed to encode stream response data envelope (error path)", logging.Fields{
				"error": err2.Error(),
			})
			return err2
		}

		closeEnv := protocol.Envelope{
			Type: protocol.MessageTypeStreamClose,
			StreamClose: &protocol.StreamClose{
				ID:    streamID,
				Error: errMsg,
			},
		}
		if err2 := codec.Encode(sess, &closeEnv); err2 != nil {
			logReq.Error("failed to encode stream response close envelope (error path)", logging.Fields{
				"error": err2.Error(),
			})
			return err2
		}

		logReq.Error("local http request failed (stream)", logging.Fields{
			"error": err.Error(),
		})
		return nil
	}
	defer res.Body.Close()

	// 응답을 StreamOpen + StreamData(4KiB chunk) + StreamClose 프레임으로 전송합니다. (ko)
	// Send the response as StreamOpen + StreamData (4KiB chunks) + StreamClose frames. (en)

	// 응답 헤더 맵을 복사하고 상태 코드를 pseudo-header 로 추가합니다. (ko)
	// Copy response headers and attach status code as a pseudo-header. (en)
	streamRespHeader := make(map[string][]string, len(res.Header)+1)
	for k, vs := range res.Header {
		streamRespHeader[k] = append([]string(nil), vs...)
	}
	statusCode := res.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	streamRespHeader[protocol.HeaderKeyStatus] = []string{strconv.Itoa(statusCode)}

	respOpen := protocol.Envelope{
		Type: protocol.MessageTypeStreamOpen,
		StreamOpen: &protocol.StreamOpen{
			ID:         streamID,
			Service:    so.Service,
			TargetAddr: so.TargetAddr,
			Header:     streamRespHeader,
		},
	}

	if err := codec.Encode(sess, &respOpen); err != nil {
		logReq.Error("failed to encode stream response open envelope", logging.Fields{
			"error": err.Error(),
		})
		return err
	}

	// 응답 바디를 4KiB(StreamChunkSize) 단위로 잘라 StreamData 프레임으로 전송합니다. (ko)
	// Chunk the response body into 4KiB (StreamChunkSize) StreamData frames. (en)
	var seq uint64
	chunk := make([]byte, protocol.StreamChunkSize)
	for {
		n, err := res.Body.Read(chunk)
		if n > 0 {
			dataCopy := append([]byte(nil), chunk[:n]...)
			// 송신 측 ARQ: Seq 별 payload 를 기록해 두었다가, StreamAck 의 LostSeqs 를 기반으로 재전송할 수 있습니다.
			sender.register(seq, dataCopy)

			dataEnv := protocol.Envelope{
				Type: protocol.MessageTypeStreamData,
				StreamData: &protocol.StreamData{
					ID:   streamID,
					Seq:  seq,
					Data: dataCopy,
				},
			}
			if err2 := codec.Encode(sess, &dataEnv); err2 != nil {
				logReq.Error("failed to encode stream response data envelope", logging.Fields{
					"error": err2.Error(),
				})
				return err2
			}
			seq++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read http response body for streaming: %w", err)
		}
	}

	closeEnv := protocol.Envelope{
		Type: protocol.MessageTypeStreamClose,
		StreamClose: &protocol.StreamClose{
			ID:    streamID,
			Error: "",
		},
	}

	if err := codec.Encode(sess, &closeEnv); err != nil {
		logReq.Error("failed to encode stream response close envelope", logging.Fields{
			"error": err.Error(),
		})
		return err
	}

	logReq.Info("stream http response sent to server", logging.Fields{
		"status":     statusCode,
		"elapsed_ms": time.Since(start).Milliseconds(),
		"error":      "",
	})

	return nil
}

// forwardToLocal 는 protocol.Request 를 로컬 HTTP 요청으로 변환하고 protocol.Response 를 채웁니다. (ko)
// forwardToLocal converts a protocol.Request into a local HTTP request and fills protocol.Response. (en)
func (p *ClientProxy) forwardToLocal(ctx context.Context, preq *protocol.Request, presp *protocol.Response) error {
	if p.LocalTarget == "" {
		return fmt.Errorf("local target is empty")
	}

	// 요청 URL을 local target 기준으로 재구성
	u, err := url.Parse(preq.URL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	u.Scheme = "http"
	u.Host = p.LocalTarget

	req, err := http.NewRequestWithContext(ctx, preq.Method, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create http request: %w", err)
	}
	// Body 설정 (원본 바이트를 그대로 사용)
	if len(preq.Body) > 0 {
		buf := bytes.NewReader(preq.Body)
		req.Body = io.NopCloser(buf)
		req.ContentLength = int64(len(preq.Body))
	}
	// 헤더 복사
	for k, vs := range preq.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	res, err := p.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform http request: %w", err)
	}
	defer res.Body.Close()

	presp.Status = res.StatusCode
	for k, vs := range res.Header {
		presp.Header[k] = append([]string(nil), vs...)
	}

	// DTLS over UDP has an upper bound on packet size (~64KiB). 전체 HTTP 바디를
	// 하나의 Envelope 로 감싸 전송하는 현재 설계에서는, 바디가 너무 크면
	// OS 레벨에서 "message too long" (EMSGSIZE) 가 발생할 수 있습니다. (ko)
	//
	// 이를 피하기 위해, 터널링 가능한 **단일 HTTP 바디** 크기에 상한을 두고,
	// 이를 초과하는 응답은 502 Bad Gateway + HopGate 전용 에러 메시지로 대체합니다. (ko)
	//
	// DTLS over UDP has an upper bound on datagram size (~64KiB). With the current
	// single-envelope design, very large bodies can still trigger "message too long"
	// (EMSGSIZE) at the OS level. To avoid this, we cap the tunneled HTTP body size
	// and replace oversized responses with a 502 Bad Gateway + HopGate-specific
	// error body. (en)
	//
	// Protobuf 기반 터널링에서는 향후 StreamData(4KiB) 단위로 나누어 전송할 예정이지만,
	// 그 전 단계에서도 body 자체를 4KiB( StreamChunkSize )로 하드 리밋하여
	// Proto message body 필드가 지나치게 커지지 않도록 합니다. (ko)
	//
	// Even before full stream tunneling is implemented, we hard-limit the protobuf
	// body field to 4KiB (StreamChunkSize) so that individual messages remain small. (en)
	const maxTunnelBodyBytes = protocol.StreamChunkSize

	limited := &io.LimitedReader{
		R: res.Body,
		N: maxTunnelBodyBytes + 1, // read up to limit+1 to detect overflow
	}
	body, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read http response body: %w", err)
	}
	if len(body) > maxTunnelBodyBytes {
		// 응답 바디가 너무 커서 DTLS/UDP 로 안전하게 전송하기 어렵기 때문에,
		// 원본 바디 대신 HopGate 에러 응답으로 대체합니다. (ko)
		//
		// The response body is too large to be safely tunneled over DTLS/UDP.
		// Replace it with a HopGate error response instead of attempting to
		// send an oversized datagram. (en)
		presp.Status = http.StatusBadGateway
		presp.Header = map[string][]string{
			"Content-Type": {"text/plain; charset=utf-8"},
		}
		presp.Body = []byte("HopGate: response body too large for DTLS tunnel (over max_tunnel_body_bytes)")
		presp.Error = "response body too large for DTLS tunnel"
		return nil
	}

	presp.Body = body

	return nil
}

// firstHeaderValue 는 주어진 키의 첫 번째 헤더 값을 반환하고, 없으면 기본값을 반환합니다. (ko)
// firstHeaderValue returns the first header value for a key, or a default if absent. (en)
func firstHeaderValue(hdr map[string][]string, key, def string) string {
	if hdr == nil {
		return def
	}
	if vs, ok := hdr[key]; ok && len(vs) > 0 {
		return vs[0]
	}
	return def
}
