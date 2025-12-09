package protocol

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

// mockDatagramConn simulates a datagram-based connection (like DTLS over UDP)
// where each Write sends a separate message and each Read receives a complete message.
// This mock verifies the FIXED behavior where the codec properly handles message boundaries.
type mockDatagramConn struct {
	messages [][]byte
	readIdx  int
}

func newMockDatagramConn() *mockDatagramConn {
	return &mockDatagramConn{
		messages: make([][]byte, 0),
	}
}

func (m *mockDatagramConn) Write(p []byte) (n int, err error) {
	// Simulate datagram behavior: each Write is a separate message
	msg := make([]byte, len(p))
	copy(msg, p)
	m.messages = append(m.messages, msg)
	return len(p), nil
}

func (m *mockDatagramConn) Read(p []byte) (n int, err error) {
	// Simulate datagram behavior: each Read returns a complete message
	if m.readIdx >= len(m.messages) {
		return 0, io.EOF
	}
	msg := m.messages[m.readIdx]
	m.readIdx++
	if len(p) < len(msg) {
		return 0, io.ErrShortBuffer
	}
	copy(p, msg)
	return len(msg), nil
}

// TestProtobufCodecDatagramBehavior tests that the protobuf codec works correctly
// with datagram-based transports (like DTLS over UDP) where message boundaries are preserved.
func TestProtobufCodecDatagramBehavior(t *testing.T) {
	codec := protobufCodec{}
	conn := newMockDatagramConn()

	// Create a test envelope
	testEnv := &Envelope{
		Type: MessageTypeHTTP,
		HTTPRequest: &Request{
			RequestID:   "test-req-123",
			ClientID:    "client-1",
			ServiceName: "test-service",
			Method:      "GET",
			URL:         "/test/path",
			Header: map[string][]string{
				"User-Agent": {"test-client"},
			},
			Body: []byte("test body content"),
		},
	}

	// Encode the envelope
	if err := codec.Encode(conn, testEnv); err != nil {
		t.Fatalf("Failed to encode envelope: %v", err)
	}

	// Verify that exactly one message was written (length prefix + data in single Write)
	if len(conn.messages) != 1 {
		t.Fatalf("Expected 1 message to be written, got %d", len(conn.messages))
	}

	// Verify the message structure: [4-byte length][protobuf data]
	msg := conn.messages[0]
	if len(msg) < 4 {
		t.Fatalf("Message too short: %d bytes", len(msg))
	}

	// Decode the envelope using a buffered reader (as we do in actual code)
	// to handle datagram-based reading properly
	reader := bufio.NewReaderSize(conn, GetDTLSReadBufferSize())
	var decodedEnv Envelope
	if err := codec.Decode(reader, &decodedEnv); err != nil {
		t.Fatalf("Failed to decode envelope: %v", err)
	}

	// Verify the decoded envelope matches the original
	if decodedEnv.Type != testEnv.Type {
		t.Errorf("Type mismatch: got %v, want %v", decodedEnv.Type, testEnv.Type)
	}
	if decodedEnv.HTTPRequest == nil {
		t.Fatal("HTTPRequest is nil after decode")
	}
	if decodedEnv.HTTPRequest.RequestID != testEnv.HTTPRequest.RequestID {
		t.Errorf("RequestID mismatch: got %v, want %v", decodedEnv.HTTPRequest.RequestID, testEnv.HTTPRequest.RequestID)
	}
	if decodedEnv.HTTPRequest.Method != testEnv.HTTPRequest.Method {
		t.Errorf("Method mismatch: got %v, want %v", decodedEnv.HTTPRequest.Method, testEnv.HTTPRequest.Method)
	}
	if decodedEnv.HTTPRequest.URL != testEnv.HTTPRequest.URL {
		t.Errorf("URL mismatch: got %v, want %v", decodedEnv.HTTPRequest.URL, testEnv.HTTPRequest.URL)
	}
	if !bytes.Equal(decodedEnv.HTTPRequest.Body, testEnv.HTTPRequest.Body) {
		t.Errorf("Body mismatch: got %v, want %v", decodedEnv.HTTPRequest.Body, testEnv.HTTPRequest.Body)
	}
}

// TestProtobufCodecStreamData tests encoding/decoding of StreamData messages
func TestProtobufCodecStreamData(t *testing.T) {
	codec := protobufCodec{}
	conn := newMockDatagramConn()

	// Create a StreamData envelope
	testEnv := &Envelope{
		Type: MessageTypeStreamData,
		StreamData: &StreamData{
			ID:   StreamID("stream-123"),
			Seq:  42,
			Data: []byte("stream data payload"),
		},
	}

	// Encode
	if err := codec.Encode(conn, testEnv); err != nil {
		t.Fatalf("Failed to encode StreamData: %v", err)
	}

	// Verify single message
	if len(conn.messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(conn.messages))
	}

	// Decode using a buffered reader (as we do in actual code)
	reader := bufio.NewReaderSize(conn, GetDTLSReadBufferSize())
	var decodedEnv Envelope
	if err := codec.Decode(reader, &decodedEnv); err != nil {
		t.Fatalf("Failed to decode StreamData: %v", err)
	}

	// Verify
	if decodedEnv.Type != MessageTypeStreamData {
		t.Errorf("Type mismatch: got %v, want %v", decodedEnv.Type, MessageTypeStreamData)
	}
	if decodedEnv.StreamData == nil {
		t.Fatal("StreamData is nil")
	}
	if decodedEnv.StreamData.ID != testEnv.StreamData.ID {
		t.Errorf("StreamID mismatch: got %v, want %v", decodedEnv.StreamData.ID, testEnv.StreamData.ID)
	}
	if decodedEnv.StreamData.Seq != testEnv.StreamData.Seq {
		t.Errorf("Seq mismatch: got %v, want %v", decodedEnv.StreamData.Seq, testEnv.StreamData.Seq)
	}
	if !bytes.Equal(decodedEnv.StreamData.Data, testEnv.StreamData.Data) {
		t.Errorf("Data mismatch: got %v, want %v", decodedEnv.StreamData.Data, testEnv.StreamData.Data)
	}
}

// TestProtobufCodecMultipleMessages tests encoding/decoding multiple messages
func TestProtobufCodecMultipleMessages(t *testing.T) {
	codec := protobufCodec{}
	conn := newMockDatagramConn()

	// Create multiple test envelopes
	envelopes := []*Envelope{
		{
			Type: MessageTypeStreamOpen,
			StreamOpen: &StreamOpen{
				ID:         StreamID("stream-1"),
				Service:    "test-service",
				TargetAddr: "127.0.0.1:8080",
			},
		},
		{
			Type: MessageTypeStreamData,
			StreamData: &StreamData{
				ID:   StreamID("stream-1"),
				Seq:  1,
				Data: []byte("first chunk"),
			},
		},
		{
			Type: MessageTypeStreamData,
			StreamData: &StreamData{
				ID:   StreamID("stream-1"),
				Seq:  2,
				Data: []byte("second chunk"),
			},
		},
		{
			Type: MessageTypeStreamClose,
			StreamClose: &StreamClose{
				ID:    StreamID("stream-1"),
				Error: "",
			},
		},
	}

	// Encode all messages
	for i, env := range envelopes {
		if err := codec.Encode(conn, env); err != nil {
			t.Fatalf("Failed to encode message %d: %v", i, err)
		}
	}

	// Verify that each encode produced exactly one message
	if len(conn.messages) != len(envelopes) {
		t.Fatalf("Expected %d messages, got %d", len(envelopes), len(conn.messages))
	}

	// Decode and verify all messages using a buffered reader (as we do in actual code)
	reader := bufio.NewReaderSize(conn, GetDTLSReadBufferSize())
	for i := 0; i < len(envelopes); i++ {
		var decoded Envelope
		if err := codec.Decode(reader, &decoded); err != nil {
			t.Fatalf("Failed to decode message %d: %v", i, err)
		}
		if decoded.Type != envelopes[i].Type {
			t.Errorf("Message %d type mismatch: got %v, want %v", i, decoded.Type, envelopes[i].Type)
		}
	}
}
