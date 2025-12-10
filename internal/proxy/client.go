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

// streamReceiver 는 단일 스트림(ID)에 대한 클라이언트 측 수신 상태와
// 로컬 HTTP 매핑을 담당하는 per-stream 구조체 설계입니다. (ko)
// streamReceiver is the per-stream receiver that owns client-side RX state
// and local HTTP mapping for a single stream ID. (en)
//
// 3.3B.2 설계 포인트:
//   - 중앙 readLoop(StartLoop)는 DTLS 세션에서 Envelope 만 읽고,
//     streamReceiver.inCh 로 `StreamOpen/StreamData/StreamClose` 를 전달합니다.
//   - streamReceiver 는 자신에게 전달된 Envelope 들만 사용해
//   - 수신 ARQ(expectedSeq/received/lost) 를 관리하고,
//   - HTTP 요청/응답을 구성해 역방향 StreamOpen/StreamData/StreamClose 를 전송합니다.
//   - 실제 run 로직 및 StartLoop 와의 통합은 3.3B.3 단계에서 구현할 예정입니다.
type streamReceiver struct {
	// 이 수신기가 담당하는 스트림 ID.
	id protocol.StreamID

	// 수신 ARQ 상태: per-stream 시퀀스 및 out-of-order 버퍼/누락 집합. (ko)
	// Receive-side ARQ state: per-stream sequence and out-of-order/lost sets. (en)
	expectedSeq uint64
	received    map[uint64][]byte
	lost        map[uint64]struct{}

	// 중앙 readLoop → per-stream goroutine 으로 전달되는 입력 채널. (ko)
	// Input channel for envelopes dispatched from the central readLoop. (en)
	inCh chan *protocol.Envelope

	// DTLS 세션 및 직렬화 codec / 로깅 핸들. (ko)
	// DTLS session, wire codec and logging handles. (en)
	sess   dtls.Session
	codec  protocol.WireCodec
	logger logging.Logger

	// 로컬 HTTP 클라이언트 및 타깃 주소 정보. (ko)
	// Local HTTP client and target information. (en)
	HTTPClient  *http.Client
	LocalTarget string
}

// newStreamReceiver 는 단일 스트림 ID 에 대한 수신 상태/HTTP 매핑을 담당하는
// streamReceiver 인스턴스를 초기화합니다. (ko)
// newStreamReceiver initializes a streamReceiver for a single stream ID. (en)
func newStreamReceiver(
	id protocol.StreamID,
	sess dtls.Session,
	codec protocol.WireCodec,
	logger logging.Logger,
	httpClient *http.Client,
	localTarget string,
) *streamReceiver {
	if codec == nil {
		codec = protocol.DefaultCodec
	}
	return &streamReceiver{
		id:          id,
		expectedSeq: 0,
		received:    make(map[uint64][]byte),
		lost:        make(map[uint64]struct{}),
		inCh:        make(chan *protocol.Envelope, 16),
		sess:        sess,
		codec:       codec,
		logger:      logger,
		HTTPClient:  httpClient,
		LocalTarget: localTarget,
	}
}

// run 은 단일 스트림에 대해 서버→클라이언트 방향 프레임을 처리하고,
// 로컬 HTTP 요청/응답을 수행한 뒤, 클라이언트→서버 방향 스트림 응답을
// 전송하는 수명주기 전담 루프입니다. (ko)
// run is the per-stream lifecycle loop that consumes inbound frames,
// performs the local HTTP request/response, and sends the reverse stream
// back to the server. (en)
func (r *streamReceiver) run(ctx context.Context, so *protocol.StreamOpen, sender *streamSender) error {
	codec := r.codec
	if codec == nil {
		codec = protocol.DefaultCodec
	}
	log := r.logger
	if log == nil {
		log = logging.NewStdJSONLogger("client_proxy_stream_receiver")
	}

	streamID := r.id

	// Pseudo-header 에서 HTTP 메타데이터를 추출합니다. (ko)
	// Extract HTTP metadata from pseudo-headers. (en)
	method := firstHeaderValue(so.Header, protocol.HeaderKeyMethod, http.MethodGet)
	urlStr := firstHeaderValue(so.Header, protocol.HeaderKeyURL, "/")
	_ = firstHeaderValue(so.Header, protocol.HeaderKeyHost, "")

	if r.LocalTarget == "" {
		return fmt.Errorf("local target is empty")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("parse url from stream_open: %w", err)
	}
	u.Scheme = "http"
	u.Host = r.LocalTarget

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
	// 동시에 수신 측 ARQ 상태(expectedSeq / out-of-order 버퍼 / LostSeqs)를 관리하고
	// StreamAck 를 전송해 선택적 재전송(Selective Retransmission)을 유도합니다.
	var bodyBuf bytes.Buffer
	const maxLostReport = 32

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case env, ok := <-r.inCh:
			if !ok {
				return fmt.Errorf("stream receiver channel closed before stream_close")
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
				case sd.Seq == r.expectedSeq:
					// 기대하던 순서의 프레임: 바로 bodyBuf 에 기록하고, 이후 버퍼된 연속 프레임도 flush.
					if len(sd.Data) > 0 {
						if _, err := bodyBuf.Write(sd.Data); err != nil {
							return fmt.Errorf("buffer stream_data: %w", err)
						}
					}
					r.expectedSeq++
					for {
						data, ok := r.received[r.expectedSeq]
						if !ok {
							break
						}
						if len(data) > 0 {
							if _, err := bodyBuf.Write(data); err != nil {
								return fmt.Errorf("buffer reordered stream_data: %w", err)
							}
						}
						delete(r.received, r.expectedSeq)
						delete(r.lost, r.expectedSeq)
						r.expectedSeq++
					}

					// AckSeq 이전 구간의 lost 항목 정리
					for seq := range r.lost {
						if seq < r.expectedSeq {
							delete(r.lost, seq)
						}
					}

				case sd.Seq > r.expectedSeq:
					// 앞선 일부 Seq 들이 누락된 상태: 현재 프레임을 버퍼링하고 missing seq 들을 lost 에 추가.
					if len(sd.Data) > 0 {
						buf := make([]byte, len(sd.Data))
						copy(buf, sd.Data)
						r.received[sd.Seq] = buf
					}
					for seq := r.expectedSeq; seq < sd.Seq && len(r.lost) < maxLostReport; seq++ {
						if _, ok := r.lost[seq]; !ok {
							r.lost[seq] = struct{}{}
						}
					}

				default:
					// sd.Seq < expectedSeq 인 경우: 이미 처리했거나 Ack 로 커버된 프레임 → 무시.
				}

				// 수신 측 StreamAck 전송:
				//   - AckSeq: 0부터 시작해 연속으로 수신 완료한 마지막 시퀀스 (expectedSeq-1)
				//   - LostSeqs: 현재 윈도우 내에서 누락된 시퀀스 중 상한 개수(maxLostReport)까지만 포함
				var ackSeq uint64
				if r.expectedSeq == 0 {
					ackSeq = 0
				} else {
					ackSeq = r.expectedSeq - 1
				}

				lostSeqs := make([]uint64, 0, len(r.lost))
				for seq := range r.lost {
					if seq >= r.expectedSeq {
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
				if err := codec.Encode(r.sess, &ackEnv); err != nil {
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
		"local_target": r.LocalTarget,
	})
	logReq.Info("received stream_open envelope from server", nil)

	res, err := r.HTTPClient.Do(req)
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
		if err2 := codec.Encode(r.sess, &respOpen); err2 != nil {
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
		if err2 := codec.Encode(r.sess, &dataEnv); err2 != nil {
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
		if err2 := codec.Encode(r.sess, &closeEnv); err2 != nil {
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

	if err := codec.Encode(r.sess, &respOpen); err != nil {
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
			if err2 := codec.Encode(r.sess, &dataEnv); err2 != nil {
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

	if err := codec.Encode(r.sess, &closeEnv); err != nil {
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

// StartLoop 는 단일 DTLS 세션에 대한 **중앙 readLoop** 역할을 수행합니다. (ko)
// StartLoop acts as the **central read loop** for a single DTLS session. (en)
//
// 3.3B.1 Design note — client-side DTLS session multiplexing:
//
// - 목표:
//   - DTLS 세션 레벨에서는 오직 `protocol.Envelope` 를 연속해서 읽고(decoding),
//     각 Envelope 를 **스트림 단위로 demux** 하는 역할만 맡습니다.
//   - 실제 HTTP 처리(요청 바디 수신, 로컬 HTTP 호출, 응답 스트림 전송)는
//     개별 스트림 전용 goroutine/구조체(`streamReceiver` 등)가 담당하도록 분리합니다.
//
// - 스트림 demux 자료구조(계획):
//   - `recvTable: map[protocol.StreamID]*streamReceiver` 형태의 수신 테이블을 유지합니다.
//   - 각 `streamReceiver` 는 자신만의 입력 채널을 가집니다. 예: `inCh chan *protocol.Envelope`.
//   - 중앙 readLoop 는 DTLS 세션에서 Envelope 를 읽은 뒤,
//   - `env.Type == MessageTypeStreamOpen` 인 경우:
//   - `id := env.StreamOpen.ID` 로 stream ID 를 구하고,
//   - `recvTable[id]` 가 없으면 새 `streamReceiver` 를 생성해 goroutine 을 띄운 뒤
//     첫 메시지(`env`)를 `receiver.inCh <- env` 로 전달합니다.
//   - `env.Type == MessageTypeStreamData` / `MessageTypeStreamClose` 인 경우:
//   - `id := env.StreamData.ID` 또는 `env.StreamClose.ID` 로 stream ID 를 구하고,
//   - 기존 `recvTable[id]` 를 찾아 `receiver.inCh <- env` 로 전달합니다.
//   - receiver 가 존재하지 않으면 해당 스트림에 한정된 프로토콜 에러로 처리할지 정책을 정의합니다.
//   - `env.Type == MessageTypeStreamAck` 인 경우:
//   - 이미 구현된 송신 측 ARQ 테이블(`streamSenders`)을 조회해 재전송 로직에 전달합니다.
//
// - 현재 구현 상태와 향후 리팩터링 경계:
//   - 지금은 `MessageTypeStreamOpen` 을 수신하면 곧바로 `handleStreamRequest` 를 호출하고,
//     이 함수가 `reader` 를 직접 소비하면서 같은 세션 안에 **동시에 하나의 스트림만** 처리할 수 있습니다.
//   - 3.3B.2 / 3.3B.3 단계에서는 위에서 설명한 demux 설계에 맞춰
//   - `handleStreamRequest` 내부 HTTP 매핑 로직을 `streamReceiver` 로 옮기고,
//   - StartLoop 가 DTLS 세션 → per-stream goroutine 으로 이벤트를 분배하는 역할만 수행하도록
//     점진적으로 리팩터링할 예정입니다.
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

	// 스트림 수신기 테이블: 중앙 readLoop 가 StreamOpen/Data/Close 를
	// 각 streamReceiver 로 demux 하기 위해 사용합니다. (ko)
	// Per-session stream receiver table used by the central read loop to
	// demultiplex StreamOpen/Data/Close frames. (en)
	receivers := make(map[protocol.StreamID]*streamReceiver)
	var receiversMu sync.Mutex

	getReceiver := func(id protocol.StreamID) *streamReceiver {
		receiversMu.Lock()
		defer receiversMu.Unlock()
		return receivers[id]
	}

	addReceiver := func(id protocol.StreamID, rcv *streamReceiver) {
		receiversMu.Lock()
		receivers[id] = rcv
		receiversMu.Unlock()
	}

	removeReceiver := func(id protocol.StreamID) {
		receiversMu.Lock()
		delete(receivers, id)
		receiversMu.Unlock()
	}

	closeAllReceivers := func() {
		receiversMu.Lock()
		defer receiversMu.Unlock()
		for id, rcv := range receivers {
			close(rcv.inCh)
			delete(receivers, id)
		}
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("client proxy loop stopping due to context cancellation", logging.Fields{
				"reason": ctx.Err().Error(),
			})
			closeAllReceivers()
			return nil
		default:
		}

		var env protocol.Envelope
		if err := codec.Decode(bufferedReader, &env); err != nil {
			if err == io.EOF {
				log.Info("dtls session closed by server", nil)
				closeAllReceivers()
				return nil
			}
			log.Error("failed to decode protocol envelope", logging.Fields{
				"error": err.Error(),
			})
			closeAllReceivers()
			return err
		}

		switch env.Type {
		case protocol.MessageTypeHTTP:
			if err := p.handleHTTPEnvelope(ctx, sess, &env); err != nil {
				log.Error("failed to handle http envelope", logging.Fields{
					"error": err.Error(),
				})
				closeAllReceivers()
				return err
			}

		case protocol.MessageTypeStreamAck:
			// 송신 측 ARQ: 서버 → 클라이언트 응답 스트림에 대한 StreamAck 처리. (ko)
			// Sender-side ARQ: handle StreamAck for response streams (server → client). (en)
			sa := env.StreamAck
			if sa == nil {
				log.Error("received stream_ack envelope with nil payload", nil)
				closeAllReceivers()
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
			// LostSeqs 를 기반으로 선택적 재전송 수행 (Selective Retransmission). (ko)
			// Perform selective retransmission based on LostSeqs. (en)
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
					closeAllReceivers()
					return err
				}
				log.Info("retransmitted stream_data after stream_ack", logging.Fields{
					"stream_id": streamID,
					"seq":       seq,
				})
			}

		case protocol.MessageTypeStreamOpen:
			// 새로운 스트림에 대한 수신기 생성 및 goroutine 실행. (ko)
			// Create a new streamReceiver and start its goroutine for this stream. (en)
			so := env.StreamOpen
			if so == nil {
				log.Error("stream_open envelope missing payload", nil)
				continue
			}
			streamID := so.ID
			if streamID == "" {
				log.Error("stream_open with empty stream id", nil)
				continue
			}
			if p.LocalTarget == "" {
				closeAllReceivers()
				return fmt.Errorf("local target is empty")
			}

			if existing := getReceiver(streamID); existing != nil {
				log.Error("duplicate stream_open for existing stream", logging.Fields{
					"stream_id": streamID,
				})
				continue
			}

			sender := newStreamSender()
			p.registerStreamSender(streamID, sender)

			receiver := newStreamReceiver(streamID, sess, codec, log, p.HTTPClient, p.LocalTarget)
			addReceiver(streamID, receiver)

			go func(id protocol.StreamID, r *streamReceiver, so *protocol.StreamOpen, snd *streamSender) {
				if err := r.run(ctx, so, snd); err != nil {
					log.Error("stream receiver terminated with error", logging.Fields{
						"stream_id": id,
						"error":     err.Error(),
					})
				}
				removeReceiver(id)
				p.unregisterStreamSender(id)
			}(streamID, receiver, so, sender)

		case protocol.MessageTypeStreamData:
			// StreamData 는 중앙 readLoop 에서 해당 streamReceiver 로 demux 됩니다. (ko)
			// StreamData frames are demultiplexed to the corresponding streamReceiver. (en)
			sd := env.StreamData
			if sd == nil {
				log.Error("stream_data envelope with nil payload", nil)
				continue
			}
			streamID := sd.ID
			receiver := getReceiver(streamID)
			if receiver == nil {
				log.Warn("received stream_data for unknown stream", logging.Fields{
					"stream_id": streamID,
				})
				continue
			}
			envCopy := env
			select {
			case receiver.inCh <- &envCopy:
			case <-ctx.Done():
				closeAllReceivers()
				return nil
			}

		case protocol.MessageTypeStreamClose:
			// StreamClose 역시 중앙 readLoop 에서 해당 streamReceiver 로 전달합니다. (ko)
			// StreamClose is also forwarded from the central readLoop to streamReceiver. (en)
			sc := env.StreamClose
			if sc == nil {
				log.Error("stream_close envelope with nil payload", nil)
				continue
			}
			streamID := sc.ID
			receiver := getReceiver(streamID)
			if receiver == nil {
				log.Warn("received stream_close for unknown stream", logging.Fields{
					"stream_id": streamID,
				})
				continue
			}
			envCopy := env
			select {
			case receiver.inCh <- &envCopy:
				// 수명주기 정리는 receiver.run 내부와 goroutine 종료 시 removeReceiver 에서 수행됩니다. (ko)
				// Lifecycle cleanup is handled inside receiver.run and the goroutine's defer. (en)
			case <-ctx.Done():
				closeAllReceivers()
				return nil
			}

		default:
			log.Error("received unsupported envelope type from server", logging.Fields{
				"type": env.Type,
			})
			closeAllReceivers()
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

	if p.LocalTarget == "" {
		return fmt.Errorf("local target is empty")
	}

	// streamReceiver 를 생성해 스트림 수신/HTTP 매핑/응답 전송을 전담시킵니다. (ko)
	// Delegate per-stream RX/HTTP mapping/response to a streamReceiver. (en)
	receiver := newStreamReceiver(streamID, sess, codec, log, p.HTTPClient, p.LocalTarget)

	// streamReceiver 수명주기를 별도 goroutine 으로 실행합니다. (ko)
	// Run the streamReceiver lifecycle in a separate goroutine. (en)
	errCh := make(chan error, 1)
	go func() {
		errCh <- receiver.run(ctx, so, sender)
	}()

	for {
		var env protocol.Envelope
		if err := codec.Decode(reader, &env); err != nil {
			if err == io.EOF {
				// DTLS 세션이 조기 종료되면 receiver 에게 더 이상 프레임이 없음을 알리고 종료를 기다립니다. (ko)
				// On EOF, close the channel so receiver can terminate gracefully. (en)
				close(receiver.inCh)
				if recvErr := <-errCh; recvErr != nil {
					return recvErr
				}
				return fmt.Errorf("unexpected EOF while reading stream request body")
			}
			close(receiver.inCh)
			if recvErr := <-errCh; recvErr != nil {
				return recvErr
			}
			return fmt.Errorf("decode stream request frame: %w", err)
		}

		switch env.Type {
		case protocol.MessageTypeStreamData:
			sd := env.StreamData
			if sd == nil {
				close(receiver.inCh)
				_ = <-errCh
				return fmt.Errorf("stream_data payload is nil")
			}
			if sd.ID != streamID {
				close(receiver.inCh)
				_ = <-errCh
				return fmt.Errorf("stream_data for unexpected stream id %q (expected %q)", sd.ID, streamID)
			}
			envCopy := env
			receiver.inCh <- &envCopy

		case protocol.MessageTypeStreamClose:
			sc := env.StreamClose
			if sc == nil {
				close(receiver.inCh)
				_ = <-errCh
				return fmt.Errorf("stream_close payload is nil")
			}
			if sc.ID != streamID {
				close(receiver.inCh)
				_ = <-errCh
				return fmt.Errorf("stream_close for unexpected stream id %q (expected %q)", sc.ID, streamID)
			}
			// StreamClose 프레임을 receiver 에게 전달한 뒤 채널을 닫고 종료를 기다립니다. (ko)
			// After forwarding StreamClose, close the channel and wait for receiver to finish. (en)
			envCopy := env
			receiver.inCh <- &envCopy
			close(receiver.inCh)
			return <-errCh

		default:
			// 예상치 못한 Envelope 타입: 해당 스트림에 한정된 프로토콜 에러로 보고 receiver 를 종료합니다. (ko)
			// Unexpected envelope type: treat as per-stream protocol error and shut down receiver. (en)
			close(receiver.inCh)
			if recvErr := <-errCh; recvErr != nil {
				return recvErr
			}
			return fmt.Errorf("unexpected envelope type %q while reading stream request body", env.Type)
		}
	}
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
