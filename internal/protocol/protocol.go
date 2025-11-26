package protocol

// Request 는 서버-클라이언트 간에 전달되는 HTTP 요청을 표현합니다.
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
type Response struct {
	RequestID string
	Status    int
	Header    map[string][]string
	Body      []byte
	Error     string // 에러 발생 시 설명 메시지
}
