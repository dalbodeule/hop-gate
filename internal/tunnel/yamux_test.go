package tunnel

import (
	"context"
	"net"
	"testing"
)

func TestSessionOpenAcceptAndBidirectionalData(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	serverCh := make(chan *Session, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		session, err := NewServer(right)
		if err != nil {
			serverErrCh <- err
			return
		}
		serverCh <- session
	}()

	client, err := NewClient(left)
	if err != nil {
		t.Fatalf("create client session: %v", err)
	}
	defer client.Close()

	var server *Session
	select {
	case err := <-serverErrCh:
		t.Fatalf("create server session: %v", err)
	case server = <-serverCh:
	}
	defer server.Close()

	meta := StreamMeta{
		Kind:    "http",
		Method:  "POST",
		Path:    "/upload",
		Headers: map[string][]string{"Content-Type": {"application/octet-stream"}},
	}
	clientStream, err := client.Open(context.Background(), meta)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer clientStream.Close()

	serverStream, err := server.Accept(context.Background())
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}
	defer serverStream.Close()

	if serverStream.Meta.Kind != meta.Kind || serverStream.Meta.Path != meta.Path {
		t.Fatalf("metadata mismatch: got %#v, want %#v", serverStream.Meta, meta)
	}

	const request = "request-body"
	if _, err := clientStream.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	buf := make([]byte, len(request))
	if _, err := serverStream.Read(buf); err != nil {
		t.Fatalf("read request: %v", err)
	}
	if string(buf) != request {
		t.Fatalf("request mismatch: got %q, want %q", buf, request)
	}

	const response = "response-body"
	if _, err := serverStream.Write([]byte(response)); err != nil {
		t.Fatalf("write response: %v", err)
	}
	buf = make([]byte, len(response))
	if _, err := clientStream.Read(buf); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(buf) != response {
		t.Fatalf("response mismatch: got %q, want %q", buf, response)
	}
}
