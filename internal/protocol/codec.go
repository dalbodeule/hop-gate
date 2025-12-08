package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	protocolpb "github.com/dalbodeule/hop-gate/internal/protocol/pb"
	"google.golang.org/protobuf/proto"
)

// defaultDecoderBufferSize 는 pion/dtls 가 복호화한 애플리케이션 데이터를
// JSON 디코더가 안전하게 처리할 수 있도록 사용하는 버퍼 크기입니다.
// This matches existing 64KiB readers used around DTLS sessions (used by the JSON codec).
const defaultDecoderBufferSize = 64 * 1024

// maxProtoEnvelopeBytes 는 단일 Protobuf Envelope 의 최대 크기에 대한 보수적 상한입니다.
// 아직 하드 리미트로 사용하지는 않지만, 향후 방어적 체크에 사용할 수 있습니다.
const maxProtoEnvelopeBytes = 512 * 1024 // 512KiB, 충분히 여유 있는 값

// WireCodec 는 protocol.Envelope 의 직렬화/역직렬화를 추상화합니다.
// JSON, Protobuf, length-prefixed binary 등으로 교체할 때 이 인터페이스만 유지하면 됩니다.
type WireCodec interface {
	Encode(w io.Writer, env *Envelope) error
	Decode(r io.Reader, env *Envelope) error
}

// jsonCodec 은 JSON 기반 WireCodec 구현입니다.
// JSON 직렬화를 계속 사용하고 싶을 때를 위해 남겨둡니다.
type jsonCodec struct{}

// Encode 는 Envelope 를 JSON 으로 인코딩해 작성합니다.
// Encode encodes an Envelope as JSON to the given writer.
func (jsonCodec) Encode(w io.Writer, env *Envelope) error {
	enc := json.NewEncoder(w)
	return enc.Encode(env)
}

// Decode 는 DTLS 세션에서 읽은 데이터를 JSON Envelope 로 디코딩합니다.
// pion/dtls 의 버퍼 특성 때문에, 충분히 큰 bufio.Reader 로 감싸서 사용합니다.
// Decode decodes an Envelope from JSON using a buffered reader on top of the DTLS session.
func (jsonCodec) Decode(r io.Reader, env *Envelope) error {
	dec := json.NewDecoder(bufio.NewReaderSize(r, defaultDecoderBufferSize))
	return dec.Decode(env)
}

// protobufCodec 은 Protobuf + length-prefix framing 기반 WireCodec 구현입니다.
// 한 Envelope 당 [4바이트 big-endian 길이] + [protobuf bytes] 형태로 인코딩합니다.
type protobufCodec struct{}

// Encode 는 Envelope 를 Protobuf Envelope 로 변환한 뒤, length-prefix 프레이밍으로 기록합니다.
// Encode encodes an Envelope as a length-prefixed protobuf message.
func (protobufCodec) Encode(w io.Writer, env *Envelope) error {
	pbEnv, err := toProtoEnvelope(env)
	if err != nil {
		return err
	}
	data, err := proto.Marshal(pbEnv)
	if err != nil {
		return fmt.Errorf("protobuf marshal envelope: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("protobuf codec: empty marshaled envelope")
	}

	var lenBuf [4]byte
	if len(data) > int(^uint32(0)) {
		return fmt.Errorf("protobuf codec: envelope too large: %d bytes", len(data))
	}
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))

	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("protobuf codec: write length prefix: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("protobuf codec: write payload: %w", err)
	}
	return nil
}

// Decode 는 length-prefix 프레임에서 Protobuf Envelope 를 읽어들여
// 내부 Envelope 구조체로 변환합니다.
// Decode reads a length-prefixed protobuf Envelope and converts it into the internal Envelope.
func (protobufCodec) Decode(r io.Reader, env *Envelope) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return fmt.Errorf("protobuf codec: read length prefix: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		return fmt.Errorf("protobuf codec: zero-length envelope")
	}
	if n > maxProtoEnvelopeBytes {
		return fmt.Errorf("protobuf codec: envelope too large: %d bytes (max %d)", n, maxProtoEnvelopeBytes)
	}

	buf := make([]byte, int(n))
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("protobuf codec: read payload: %w", err)
	}

	var pbEnv protocolpb.Envelope
	if err := proto.Unmarshal(buf, &pbEnv); err != nil {
		return fmt.Errorf("protobuf codec: unmarshal envelope: %w", err)
	}

	return fromProtoEnvelope(&pbEnv, env)
}

// DefaultCodec 은 현재 런타임에서 사용하는 기본 WireCodec 입니다.
// 이제 Protobuf 기반 codec 을 기본으로 사용합니다.
var DefaultCodec WireCodec = protobufCodec{}

// toProtoEnvelope 는 내부 Envelope 구조체를 Protobuf Envelope 로 변환합니다.
// 현재 구현은 HTTP 요청/응답 및 스트림 관련 타입(StreamOpen/StreamData/StreamClose/StreamAck)을 지원합니다.
func toProtoEnvelope(env *Envelope) (*protocolpb.Envelope, error) {
	switch env.Type {
	case MessageTypeHTTP:
		if env.HTTPRequest != nil {
			req := env.HTTPRequest
			pbReq := &protocolpb.Request{
				RequestId:   req.RequestID,
				ClientId:    req.ClientID,
				ServiceName: req.ServiceName,
				Method:      req.Method,
				Url:         req.URL,
				Header:      make(map[string]*protocolpb.HeaderValues, len(req.Header)),
				Body:        req.Body,
			}
			for k, vs := range req.Header {
				hv := &protocolpb.HeaderValues{
					Values: append([]string(nil), vs...),
				}
				pbReq.Header[k] = hv
			}
			return &protocolpb.Envelope{
				Payload: &protocolpb.Envelope_HttpRequest{
					HttpRequest: pbReq,
				},
			}, nil
		}
		if env.HTTPResponse != nil {
			resp := env.HTTPResponse
			pbResp := &protocolpb.Response{
				RequestId: resp.RequestID,
				Status:    int32(resp.Status),
				Header:    make(map[string]*protocolpb.HeaderValues, len(resp.Header)),
				Body:      resp.Body,
				Error:     resp.Error,
			}
			for k, vs := range resp.Header {
				hv := &protocolpb.HeaderValues{
					Values: append([]string(nil), vs...),
				}
				pbResp.Header[k] = hv
			}
			return &protocolpb.Envelope{
				Payload: &protocolpb.Envelope_HttpResponse{
					HttpResponse: pbResp,
				},
			}, nil
		}
		return nil, fmt.Errorf("protobuf codec: http envelope has neither request nor response")
	case MessageTypeStreamOpen:
		if env.StreamOpen == nil {
			return nil, fmt.Errorf("protobuf codec: stream_open envelope missing payload")
		}
		so := env.StreamOpen
		pbSO := &protocolpb.StreamOpen{
			Id:          string(so.ID),
			ServiceName: so.Service,
			TargetAddr:  so.TargetAddr,
			Header:      make(map[string]*protocolpb.HeaderValues, len(so.Header)),
		}
		for k, vs := range so.Header {
			hv := &protocolpb.HeaderValues{
				Values: append([]string(nil), vs...),
			}
			pbSO.Header[k] = hv
		}
		return &protocolpb.Envelope{
			Payload: &protocolpb.Envelope_StreamOpen{
				StreamOpen: pbSO,
			},
		}, nil
	case MessageTypeStreamData:
		if env.StreamData == nil {
			return nil, fmt.Errorf("protobuf codec: stream_data envelope missing payload")
		}
		sd := env.StreamData
		pbSD := &protocolpb.StreamData{
			Id:   string(sd.ID),
			Seq:  sd.Seq,
			Data: sd.Data,
		}
		return &protocolpb.Envelope{
			Payload: &protocolpb.Envelope_StreamData{
				StreamData: pbSD,
			},
		}, nil
	case MessageTypeStreamClose:
		if env.StreamClose == nil {
			return nil, fmt.Errorf("protobuf codec: stream_close envelope missing payload")
		}
		sc := env.StreamClose
		pbSC := &protocolpb.StreamClose{
			Id:    string(sc.ID),
			Error: sc.Error,
		}
		return &protocolpb.Envelope{
			Payload: &protocolpb.Envelope_StreamClose{
				StreamClose: pbSC,
			},
		}, nil
	case MessageTypeStreamAck:
		if env.StreamAck == nil {
			return nil, fmt.Errorf("protobuf codec: stream_ack envelope missing payload")
		}
		sa := env.StreamAck
		pbSA := &protocolpb.StreamAck{
			Id:         string(sa.ID),
			AckSeq:     sa.AckSeq,
			LostSeqs:   append([]uint64(nil), sa.LostSeqs...),
			WindowSize: sa.WindowSize,
		}
		return &protocolpb.Envelope{
			Payload: &protocolpb.Envelope_StreamAck{
				StreamAck: pbSA,
			},
		}, nil
	default:
		return nil, fmt.Errorf("protobuf codec: unsupported envelope type %q", env.Type)
	}
}

// fromProtoEnvelope 는 Protobuf Envelope 를 내부 Envelope 구조체로 변환합니다.
// 현재 구현은 HTTP 요청/응답 및 스트림 관련 타입(StreamOpen/StreamData/StreamClose/StreamAck)을 지원합니다.
func fromProtoEnvelope(pbEnv *protocolpb.Envelope, env *Envelope) error {
	switch payload := pbEnv.Payload.(type) {
	case *protocolpb.Envelope_HttpRequest:
		req := payload.HttpRequest
		if req == nil {
			return fmt.Errorf("protobuf codec: http_request payload is nil")
		}
		hdr := make(map[string][]string, len(req.Header))
		for k, hv := range req.Header {
			if hv == nil {
				continue
			}
			hdr[k] = append([]string(nil), hv.Values...)
		}
		env.Type = MessageTypeHTTP
		env.HTTPRequest = &Request{
			RequestID:   req.RequestId,
			ClientID:    req.ClientId,
			ServiceName: req.ServiceName,
			Method:      req.Method,
			URL:         req.Url,
			Header:      hdr,
			Body:        append([]byte(nil), req.Body...),
		}
		env.HTTPResponse = nil
		env.StreamOpen = nil
		env.StreamData = nil
		env.StreamClose = nil
		env.StreamAck = nil
		return nil

	case *protocolpb.Envelope_HttpResponse:
		resp := payload.HttpResponse
		if resp == nil {
			return fmt.Errorf("protobuf codec: http_response payload is nil")
		}
		hdr := make(map[string][]string, len(resp.Header))
		for k, hv := range resp.Header {
			if hv == nil {
				continue
			}
			hdr[k] = append([]string(nil), hv.Values...)
		}
		env.Type = MessageTypeHTTP
		env.HTTPResponse = &Response{
			RequestID: resp.RequestId,
			Status:    int(resp.Status),
			Header:    hdr,
			Body:      append([]byte(nil), resp.Body...),
			Error:     resp.Error,
		}
		env.HTTPRequest = nil
		env.StreamOpen = nil
		env.StreamData = nil
		env.StreamClose = nil
		env.StreamAck = nil
		return nil

	case *protocolpb.Envelope_StreamOpen:
		so := payload.StreamOpen
		if so == nil {
			return fmt.Errorf("protobuf codec: stream_open payload is nil")
		}
		hdr := make(map[string][]string, len(so.Header))
		for k, hv := range so.Header {
			if hv == nil {
				continue
			}
			hdr[k] = append([]string(nil), hv.Values...)
		}
		env.Type = MessageTypeStreamOpen
		env.StreamOpen = &StreamOpen{
			ID:         StreamID(so.Id),
			Service:    so.ServiceName,
			TargetAddr: so.TargetAddr,
			Header:     hdr,
		}
		env.StreamData = nil
		env.StreamClose = nil
		env.StreamAck = nil
		env.HTTPRequest = nil
		env.HTTPResponse = nil
		return nil

	case *protocolpb.Envelope_StreamData:
		sd := payload.StreamData
		if sd == nil {
			return fmt.Errorf("protobuf codec: stream_data payload is nil")
		}
		env.Type = MessageTypeStreamData
		env.StreamData = &StreamData{
			ID:   StreamID(sd.Id),
			Seq:  sd.Seq,
			Data: append([]byte(nil), sd.Data...),
		}
		env.StreamOpen = nil
		env.StreamClose = nil
		env.StreamAck = nil
		env.HTTPRequest = nil
		env.HTTPResponse = nil
		return nil

	case *protocolpb.Envelope_StreamClose:
		sc := payload.StreamClose
		if sc == nil {
			return fmt.Errorf("protobuf codec: stream_close payload is nil")
		}
		env.Type = MessageTypeStreamClose
		env.StreamClose = &StreamClose{
			ID:    StreamID(sc.Id),
			Error: sc.Error,
		}
		env.StreamOpen = nil
		env.StreamData = nil
		env.StreamAck = nil
		env.HTTPRequest = nil
		env.HTTPResponse = nil
		return nil

	case *protocolpb.Envelope_StreamAck:
		sa := payload.StreamAck
		if sa == nil {
			return fmt.Errorf("protobuf codec: stream_ack payload is nil")
		}
		env.Type = MessageTypeStreamAck
		env.StreamAck = &StreamAck{
			ID:         StreamID(sa.Id),
			AckSeq:     sa.AckSeq,
			LostSeqs:   append([]uint64(nil), sa.LostSeqs...),
			WindowSize: sa.WindowSize,
		}
		env.StreamOpen = nil
		env.StreamData = nil
		env.StreamClose = nil
		env.HTTPRequest = nil
		env.HTTPResponse = nil
		return nil

	default:
		return fmt.Errorf("protobuf codec: unsupported payload type %T", payload)
	}
}
