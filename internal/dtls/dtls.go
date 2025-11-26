package dtls

import "io"

// Session 은 DTLS 위의 양방향 스트림을 추상화합니다.
type Session interface {
	io.ReadWriteCloser
	ID() string
}

// Server 는 다중 클라이언트 DTLS 세션을 관리하는 추상 인터페이스입니다.
type Server interface {
	Accept() (Session, error)
	Close() error
}

// Client 는 단일 서버와의 DTLS 세션을 관리하는 추상 인터페이스입니다.
type Client interface {
	Connect() (Session, error)
	Close() error
}

// 실제 구현은 향후 pion/dtls 등을 사용해 추가합니다.
