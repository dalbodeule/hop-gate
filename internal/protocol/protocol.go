package protocol

// Request 는 서버-클라이언트 간에 전달되는 HTTP 요청을 표현합니다.
// 기존 HTTP 터널링 경로에서는 이 구조체를 그대로 사용합니다.
type Request struct {
	RequestID   string
	ClientID    string // 대상 클라이언트 식별자
	ServiceName string // 클라이언트 내부 서비스 이름

	Method string
	URL    string
	Header map[string][]string
	Body   []byte
}

// Response 는 서버-클라이언트 간에 전달되는 HTTP 응답을 표현합니다.
// 기존 HTTP 터널링 경로에서는 이 구조체를 그대로 사용합니다.
type Response struct {
	RequestID string
	Status    int
	Header    map[string][]string
	Body      []byte
	Error     string // 에러 발생 시 설명 메시지
}

// --- 확장 가능 DTLS 메시지 Envelope 및 스트림 구조체 ---
//
// WebSocket/TCP 스트림 터널링을 지원하기 위해, 단일 HTTP 요청/응답 외에도
// 스트림 기반 메시지를 운반할 수 있는 Envelope 타입을 정의합니다.
// 현재 구현에서는 아직 사용하지 않으며, 향후 단계적으로 적용할 예정입니다.

// MessageType 은 DTLS 위에서 교환되는 상위 레벨 메시지 종류를 나타냅니다.
type MessageType string

// StreamChunkSize 는 스트림 터널링 시 단일 StreamData 프레임에 담을 최대 payload 크기입니다.
// 현재 구현에서는 4KiB 로 고정하여 DTLS/UDP MTU 한계를 여유 있게 피하도록 합니다.
// StreamChunkSize is the maximum payload size per StreamData frame (4KiB).
const StreamChunkSize = 4 * 1024

const (
	// MessageTypeHTTP 는 기존 단일 HTTP 요청/응답 메시지를 의미합니다.
	// 이 경우 HTTPRequest / HTTPResponse 필드를 사용합니다.
	MessageTypeHTTP MessageType = "http"

	// MessageTypeStreamOpen 은 새로운 스트림(TCP/WebSocket 등)의 오픈을 의미합니다.
	MessageTypeStreamOpen MessageType = "stream_open"

	// MessageTypeStreamData 는 열린 스트림에 대한 양방향 데이터 프레임을 의미합니다.
	// HTTP 바디 chunk 를 비롯한 실제 payload 는 이 타입을 통해 전송됩니다.
	// Stream data frames for an already-opened stream (HTTP body chunks, etc.).
	MessageTypeStreamData MessageType = "stream_data"

	// MessageTypeStreamClose 는 스트림 종료(정상/에러)를 의미합니다.
	// Normal or error-termination of a stream.
	MessageTypeStreamClose MessageType = "stream_close"

	// MessageTypeStreamAck 는 스트림 데이터 프레임에 대한 ACK/NACK 및 재전송 힌트를 전달합니다.
	// Stream-level ACK/NACK frames for selective retransmission hints.
	MessageTypeStreamAck MessageType = "stream_ack"
)

// Envelope 는 DTLS 세션 위에서 교환되는 상위 레벨 메시지 컨테이너입니다.
// 하나의 Envelope 에는 HTTP 요청/응답 또는 스트림 관련 메시지 중 하나만 포함됩니다.
type Envelope struct {
	Type MessageType `json:"type"`

	// HTTP 1회성 요청/응답 (기존 터널링 경로)
	HTTPRequest  *Request  `json:"http_request,omitempty"`
	HTTPResponse *Response `json:"http_response,omitempty"`

	// 스트림 기반 메시지 (WebSocket/TCP 터널용)
	StreamOpen  *StreamOpen  `json:"stream_open,omitempty"`
	StreamData  *StreamData  `json:"stream_data,omitempty"`
	StreamClose *StreamClose `json:"stream_close,omitempty"`

	// 스트림 제어 메시지 (ACK/NACK, 재전송 힌트 등)
	// Stream-level control messages (ACK/NACK, retransmission hints, etc.).
	StreamAck *StreamAck `json:"stream_ack,omitempty"`
}

// StreamID 는 스트림(예: 특정 WebSocket 연결 또는 TCP 커넥션)을 구분하기 위한 식별자입니다.
type StreamID string

// HTTP-over-stream 터널링에서 사용되는 pseudo-header 키 상수입니다.
// These pseudo-header keys are used when tunneling HTTP over the stream protocol.
const (
	HeaderKeyMethod = "X-HopGate-Method"
	HeaderKeyURL    = "X-HopGate-URL"
	HeaderKeyHost   = "X-HopGate-Host"
	HeaderKeyStatus = "X-HopGate-Status"
)

// StreamOpen 은 새로운 스트림을 여는 요청을 나타냅니다.
type StreamOpen struct {
	ID StreamID `json:"id"`

	// Service / TargetAddr 는 클라이언트 측에서 어느 로컬 서비스로 연결해야 하는지를 나타냅니다.
	// 최소 구현에서는 LocalTarget 하나만 사용해도 되며, 추후 서비스별로 확장 가능합니다.
	Service    string              `json:"service_name,omitempty"`
	TargetAddr string              `json:"target_addr,omitempty"` // 예: "127.0.0.1:8080"
	Header     map[string][]string `json:"header,omitempty"`      // 초기 HTTP 헤더(Upgrade 포함) 전달용
}

// StreamData 는 이미 열린 스트림에 대해 한 방향으로 전송되는 데이터 프레임을 표현합니다.
// DTLS/UDP 특성상 손실/중복/순서 뒤바뀜을 감지하고 재전송할 수 있도록
// 각 스트림 내에서 0부터 시작하는 시퀀스 번호(Seq)를 포함합니다.
//
// StreamData represents a unidirectional data frame on an already-opened stream.
// To support loss/duplication/reordering detection and retransmission over DTLS/UDP,
// it carries a per-stream sequence number (Seq) starting from 0.
type StreamData struct {
	ID   StreamID `json:"id"`
	Seq  uint64   `json:"seq"`
	Data []byte   `json:"data"`
}

// StreamAck 는 스트림 데이터 프레임에 대한 ACK/NACK 및 선택적 재전송 요청 정보를 전달합니다.
// AckSeq 는 수신 측에서 "연속적으로" 수신 완료한 마지막 Seq 를 의미하며,
// LostSeqs 는 그 이후 구간에서 누락된 시퀀스 번호(선택적)를 나타냅니다.
//
// StreamAck conveys ACK/NACK and optional retransmission hints for stream data frames.
// AckSeq denotes the last sequence number received contiguously by the receiver,
// while LostSeqs can list additional missing sequence numbers beyond AckSeq.
type StreamAck struct {
	ID StreamID `json:"id"`

	// AckSeq 는 수신 측에서 0부터 시작해 연속으로 수신 완료한 마지막 Seq 입니다.
	// AckSeq is the last contiguously received sequence number starting from 0.
	AckSeq uint64 `json:"ack_seq"`

	// LostSeqs 는 AckSeq 이후 구간에서 누락된 시퀀스 번호 목록입니다(선택).
	// 이 필드는 선택적 selective retransmission 힌트를 제공하기 위해 사용됩니다.
	//
	// LostSeqs is an optional list of missing sequence numbers beyond AckSeq,
	// used as a hint for selective retransmission.
	LostSeqs []uint64 `json:"lost_seqs,omitempty"`

	// WindowSize 는 수신 측이 허용 가능한 in-flight 프레임 수를 나타내는 선택적 힌트입니다.
	// WindowSize is an optional hint for the allowed number of in-flight frames.
	WindowSize uint32 `json:"window_size,omitempty"`
}

// StreamClose 는 스트림 종료를 알리는 메시지입니다.
type StreamClose struct {
	ID    StreamID `json:"id"`
	Error string   `json:"error,omitempty"` // 비워두면 정상 종료로 해석
}
