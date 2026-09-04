package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dalbodeule/hop-gate/internal/logging"
)

type noopLogger struct{}

func (noopLogger) Debug(string, logging.Fields)         {}
func (noopLogger) Info(string, logging.Fields)          {}
func (noopLogger) Warn(string, logging.Fields)          {}
func (noopLogger) Error(string, logging.Fields)         {}
func (l noopLogger) With(logging.Fields) logging.Logger { return l }

type streamingTestTunnel struct {
	forwardHTTPCalled     bool
	extendedConnectCalled bool
	deadlineSeen          bool
}

func (t *streamingTestTunnel) ForwardHTTP(ctx context.Context, _ logging.Logger, _ *http.Request, _ string, w http.ResponseWriter) error {
	t.forwardHTTPCalled = true
	_, t.deadlineSeen = ctx.Deadline()
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("data: ready\n\n"))
	return err
}

func (t *streamingTestTunnel) ForwardExtendedConnect(_ context.Context, _ logging.Logger, _ *http.Request, _ string, w http.ResponseWriter) error {
	t.extendedConnectCalled = true
	w.WriteHeader(http.StatusOK)
	return nil
}

func TestSSERequestStreamsWithoutProxyTimeout(t *testing.T) {
	tunnel := &streamingTestTunnel{}
	logger := noopLogger{}
	domain := "sse-test.example"
	registerTunnelForDomain(domain, tunnel, logger)
	defer unregisterTunnelForDomain(domain, tunnel, logger)

	req := httptest.NewRequest(http.MethodGet, "http://"+domain+"/events", nil)
	req.Host = domain
	req.Header.Set("Accept", "text/event-stream")
	recorder := httptest.NewRecorder()

	newHTTPHandler(logger, time.Nanosecond).ServeHTTP(recorder, req)

	if !tunnel.forwardHTTPCalled {
		t.Fatal("expected SSE request to use HTTP forwarder")
	}
	if tunnel.deadlineSeen {
		t.Fatal("expected SSE request to avoid the normal proxy timeout")
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}
	if got := recorder.Body.String(); got != "data: ready\n\n" {
		t.Fatalf("body = %q, want SSE event", got)
	}
}

func TestHTTP2ExtendedConnectUsesDedicatedForwarder(t *testing.T) {
	tunnel := &streamingTestTunnel{}
	logger := noopLogger{}
	domain := "h2-connect-test.example"
	registerTunnelForDomain(domain, tunnel, logger)
	defer unregisterTunnelForDomain(domain, tunnel, logger)

	req := httptest.NewRequest(http.MethodConnect, "https://"+domain+"/socket", nil)
	req.Host = domain
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Proto = "websocket"
	recorder := httptest.NewRecorder()

	newHTTPHandler(logger, time.Second).ServeHTTP(recorder, req)

	if !tunnel.extendedConnectCalled {
		t.Fatal("expected HTTP/2 Extended CONNECT forwarder to be called")
	}
	if tunnel.forwardHTTPCalled {
		t.Fatal("did not expect regular HTTP forwarder for Extended CONNECT")
	}
	if got := recorder.Code; got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
}

func TestHTTP3ExtendedConnectDetection(t *testing.T) {
	req := httptest.NewRequest(http.MethodConnect, "https://h3.example/socket", nil)
	req.ProtoMajor = 3
	req.ProtoMinor = 0
	req.Proto = "websocket"

	if !isExtendedConnectWebSocketRequest(req) {
		t.Fatal("expected HTTP/3 Extended CONNECT WebSocket request to be detected")
	}
}

func TestHTTP3SSERequestUsesStreamingPolicy(t *testing.T) {
	tunnel := &streamingTestTunnel{}
	logger := noopLogger{}
	domain := "h3-sse-test.example"
	registerTunnelForDomain(domain, tunnel, logger)
	defer unregisterTunnelForDomain(domain, tunnel, logger)

	req := httptest.NewRequest(http.MethodGet, "https://"+domain+"/events", nil)
	req.Host = domain
	req.ProtoMajor = 3
	req.ProtoMinor = 0
	req.Header.Set("Accept", "text/event-stream")
	recorder := httptest.NewRecorder()

	newHTTPHandler(logger, time.Nanosecond).ServeHTTP(recorder, req)

	if tunnel.deadlineSeen {
		t.Fatal("expected HTTP/3 SSE request to avoid the normal proxy timeout")
	}
	if got := recorder.Body.String(); got != "data: ready\n\n" {
		t.Fatalf("body = %q, want SSE event", got)
	}
}
