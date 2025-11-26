package dtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	piondtls "github.com/pion/dtls/v3"
)

// pionSession 은 pion/dtls.Conn 을 감싸 Session 인터페이스를 구현합니다.
type pionSession struct {
	conn *piondtls.Conn
	id   string
}

func (s *pionSession) Read(b []byte) (int, error)  { return s.conn.Read(b) }
func (s *pionSession) Write(b []byte) (int, error) { return s.conn.Write(b) }
func (s *pionSession) Close() error                { return s.conn.Close() }
func (s *pionSession) ID() string                  { return s.id }

// pionServer 는 pion/dtls 기반 Server 구현입니다.
type pionServer struct {
	listener net.Listener
}

// PionServerConfig 는 DTLS 서버 리스너 구성을 정의합니다.
type PionServerConfig struct {
	// Addr 는 "0.0.0.0:443" 와 같은 UDP 리스닝 주소입니다.
	Addr string

	// TLSConfig 는 ACME 등을 통해 준비된 tls.Config 입니다.
	// Certificates, RootCAs, ClientAuth 등의 설정이 여기서 넘어옵니다.
	// nil 인 경우 기본 빈 tls.Config 가 사용됩니다.
	TLSConfig *tls.Config
}

// NewPionServer 는 pion/dtls 기반 DTLS 서버를 생성합니다.
// 내부적으로 udp 리스너를 열고, DTLS 핸드셰이크를 수행할 준비를 합니다.
func NewPionServer(cfg PionServerConfig) (Server, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("PionServerConfig.Addr is required")
	}
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr: %w", err)
	}

	dtlsCfg := &piondtls.Config{
		Certificates:       cfg.TLSConfig.Certificates,
		InsecureSkipVerify: cfg.TLSConfig.InsecureSkipVerify,
		// 필요 시 RootCAs, ClientAuth, ExtendedMasterSecret 등을 추가 설정
	}

	l, err := piondtls.Listen("udp", udpAddr, dtlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dtls listen: %w", err)
	}

	return &pionServer{
		listener: l,
	}, nil
}

// Accept 는 새로운 DTLS 연결을 수락하고, Session 으로 래핑합니다.
func (s *pionServer) Accept() (Session, error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	dtlsConn, ok := conn.(*piondtls.Conn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("accepted connection is not *dtls.Conn")
	}

	id := ""
	if ra := dtlsConn.RemoteAddr(); ra != nil {
		id = ra.String()
	}

	return &pionSession{
		conn: dtlsConn,
		id:   id,
	}, nil
}

// Close 는 DTLS 리스너를 종료합니다.
func (s *pionServer) Close() error {
	return s.listener.Close()
}

// pionClient 는 pion/dtls 기반 Client 구현입니다.
type pionClient struct {
	addr      string
	tlsConfig *tls.Config
	timeout   time.Duration
}

// PionClientConfig 는 DTLS 클라이언트 구성을 정의합니다.
type PionClientConfig struct {
	// Addr 는 서버의 UDP 주소 (예: "example.com:443") 입니다.
	Addr string

	// TLSConfig 는 서버 인증에 사용할 tls.Config 입니다.
	// InsecureSkipVerify=true 로 두면 서버 인증을 건너뛰므로 개발/테스트에만 사용해야 합니다.
	TLSConfig *tls.Config

	// Timeout 은 DTLS 핸드셰이크 타임아웃입니다.
	// 0 이면 기본값 10초가 사용됩니다.
	Timeout time.Duration
}

// NewPionClient 는 pion/dtls 기반 DTLS 클라이언트를 생성합니다.
func NewPionClient(cfg PionClientConfig) Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.TLSConfig == nil {
		// 기본값: 인증서 검증을 수행하는 안전한 설정(루트 CA 체인은 시스템 기본값 사용).
		// 디버그 모드에서 인증서 검증을 스킵하고 싶다면, 호출 측에서
		// TLSConfig: &tls.Config{InsecureSkipVerify: true} 를 명시적으로 전달해야 합니다.
		cfg.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}
	return &pionClient{
		addr:      cfg.Addr,
		tlsConfig: cfg.TLSConfig,
		timeout:   cfg.Timeout,
	}
}

// Connect 는 서버와 DTLS 핸드셰이크를 수행하고 Session 을 반환합니다.
func (c *pionClient) Connect() (Session, error) {
	if c.addr == "" {
		return nil, fmt.Errorf("PionClientConfig.Addr is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	raddr, err := net.ResolveUDPAddr("udp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr: %w", err)
	}

	dtlsCfg := &piondtls.Config{
		Certificates:       c.tlsConfig.Certificates,
		InsecureSkipVerify: c.tlsConfig.InsecureSkipVerify,
		// 필요 시 ServerName, RootCAs 등 추가 설정
	}

	type result struct {
		conn *piondtls.Conn
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		conn, err := piondtls.Dial("udp", raddr, dtlsCfg)
		ch <- result{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("dtls dial timeout: %w", ctx.Err())
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("dtls dial: %w", res.err)
		}
		id := ""
		if ra := res.conn.RemoteAddr(); ra != nil {
			id = ra.String()
		}
		return &pionSession{
			conn: res.conn,
			id:   id,
		}, nil
	}
}

// Close 는 클라이언트 단에서 유지하는 리소스가 없으므로 no-op 입니다.
func (c *pionClient) Close() error {
	return nil
}
