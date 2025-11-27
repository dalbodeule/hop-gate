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

const (
	// MessageTypeHTTP 는 기존 단일 HTTP 요청/응답 메시지를 의미합니다.
	// 이 경우 HTTPRequest / HTTPResponse 필드를 사용합니다.
	MessageTypeHTTP MessageType = "http"

	// MessageTypeStreamOpen 은 새로운 스트림(TCP/WebSocket 등)의 오픈을 의미합니다.
	MessageTypeStreamOpen MessageType = "stream_open"

	// MessageTypeStreamData 는 열린 스트림에 대한 양방향 데이터 프레임을 의미합니다.
	MessageTypeStreamData MessageType = "stream_data"

	// MessageTypeStreamClose 는 스트림 종료(정상/에러)를 의미합니다.
	MessageTypeStreamClose MessageType = "stream_close"
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
}

// StreamID 는 스트림(예: 특정 WebSocket 연결 또는 TCP 커넥션)을 구분하기 위한 식별자입니다.
type StreamID string

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
type StreamData struct {
	ID   StreamID `json:"id"`
	Data []byte   `json:"data"`
}

// StreamClose 는 스트림 종료를 알리는 메시지입니다.
type StreamClose struct {
	ID    StreamID `json:"id"`
	Error string   `json:"error,omitempty"` // 비워두면 정상 종료로 해석
}
