// Package tunnel provides the transport-neutral session used by HopGate.
// The wire transport is TLS over TCP, while yamux supplies bidirectional
// logical streams on top of the connection.
package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	metadataHeaderSize = 4
	maxMetadataSize    = 64 << 10
)

// StreamMeta describes what a logical stream carries. HTTP and WebSocket
// streams use the same transport; only the metadata kind differs.
type StreamMeta struct {
	Kind    string              `json:"kind"`
	Domain  string              `json:"domain,omitempty"`
	Service string              `json:"service,omitempty"`
	Method  string              `json:"method,omitempty"`
	Path    string              `json:"path,omitempty"`
	Host    string              `json:"host,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Target  string              `json:"target,omitempty"`
}

// Stream is a yamux stream with one metadata record at its beginning.
type Stream struct {
	net.Conn
	Meta StreamMeta
}

// Session is a bidirectional multiplexed tunnel.
type Session struct {
	inner *yamux.Session
}

func newSession(conn net.Conn, server bool) (*Session, error) {
	if conn == nil {
		return nil, errors.New("tunnel: nil connection")
	}
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 30 * time.Second
	config.ConnectionWriteTimeout = 10 * time.Second

	var session *yamux.Session
	var err error
	if server {
		session, err = yamux.Server(conn, config)
	} else {
		session, err = yamux.Client(conn, config)
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel: create yamux session: %w", err)
	}
	return &Session{inner: session}, nil
}

// NewClient wraps an already-established TLS or test connection.
func NewClient(conn net.Conn) (*Session, error) { return newSession(conn, false) }

// NewServer wraps an accepted TLS or test connection.
func NewServer(conn net.Conn) (*Session, error) { return newSession(conn, true) }

// DialTLS dials the server and establishes a TLS-protected yamux session.
func DialTLS(ctx context.Context, address string, config *tls.Config) (*Session, error) {
	if config == nil {
		return nil, errors.New("tunnel: nil TLS config")
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: config}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tunnel: TLS dial: %w", err)
	}
	return NewClient(conn)
}

// Open creates a stream and writes its metadata before returning it.
func (s *Session) Open(ctx context.Context, meta StreamMeta) (*Stream, error) {
	if s == nil || s.inner == nil {
		return nil, errors.New("tunnel: session is closed")
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	conn, err := s.inner.Open()
	if err != nil {
		return nil, fmt.Errorf("tunnel: open stream: %w", err)
	}
	clearDeadline := true
	defer func() {
		if clearDeadline {
			_ = conn.SetDeadline(time.Time{})
		}
	}()
	if deadline, ok := ctxDeadline(ctx); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tunnel: set stream deadline: %w", err)
		}
	}
	if err := writeMeta(conn, meta); err != nil {
		_ = conn.Close()
		return nil, err
	}
	clearDeadline = false
	_ = conn.SetDeadline(time.Time{})
	return &Stream{Conn: conn, Meta: meta}, nil
}

// Accept waits for a peer-created stream and reads its metadata.
func (s *Session) Accept(ctx context.Context) (*Stream, error) {
	if s == nil || s.inner == nil {
		return nil, errors.New("tunnel: session is closed")
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	conn, err := s.inner.Accept()
	if err != nil {
		return nil, fmt.Errorf("tunnel: accept stream: %w", err)
	}
	if deadline, ok := ctxDeadline(ctx); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tunnel: set stream deadline: %w", err)
		}
	}
	meta, err := readMeta(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &Stream{Conn: conn, Meta: meta}, nil
}

func (s *Session) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Close()
}

// IsClosed reports whether the underlying yamux session has terminated.
func (s *Session) IsClosed() bool {
	return s == nil || s.inner == nil || s.inner.IsClosed()
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return nil
}

func ctxDeadline(ctx context.Context) (time.Time, bool) {
	if ctx == nil {
		return time.Time{}, false
	}
	return ctx.Deadline()
}

func writeMeta(w io.Writer, meta StreamMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("tunnel: encode stream metadata: %w", err)
	}
	if len(data) > maxMetadataSize {
		return fmt.Errorf("tunnel: stream metadata exceeds %d bytes", maxMetadataSize)
	}
	header := make([]byte, metadataHeaderSize)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("tunnel: write metadata length: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("tunnel: write metadata: %w", err)
	}
	return nil
}

func readMeta(r io.Reader) (StreamMeta, error) {
	header := make([]byte, metadataHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return StreamMeta{}, fmt.Errorf("tunnel: read metadata length: %w", err)
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maxMetadataSize {
		return StreamMeta{}, fmt.Errorf("tunnel: invalid metadata size %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return StreamMeta{}, fmt.Errorf("tunnel: read metadata: %w", err)
	}
	var meta StreamMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return StreamMeta{}, fmt.Errorf("tunnel: decode stream metadata: %w", err)
	}
	if meta.Kind == "" {
		return StreamMeta{}, errors.New("tunnel: stream metadata kind is required")
	}
	return meta, nil
}
