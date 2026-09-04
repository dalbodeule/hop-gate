package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dalbodeule/hop-gate/internal/logging"
	"github.com/dalbodeule/hop-gate/internal/tunnel"
)

type yamuxTunnelSession struct {
	session *tunnel.Session
	logger  logging.Logger
}

func (t *yamuxTunnelSession) ForwardHTTP(ctx context.Context, logger logging.Logger, req *http.Request, serviceName string, w http.ResponseWriter) error {
	if ctx == nil {
		ctx = context.Background()
	}
	meta := tunnel.StreamMeta{
		Kind:    "http",
		Service: serviceName,
		Method:  req.Method,
		Path:    req.URL.RequestURI(),
		Host:    req.Host,
		Headers: req.Header,
	}
	stream, err := t.session.Open(ctx, meta)
	if err != nil {
		return err
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}

	request := req.Clone(ctx)
	request.RequestURI = ""
	if err := request.Write(stream); err != nil {
		return fmt.Errorf("write HTTP request to yamux stream: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		return fmt.Errorf("read HTTP response from yamux stream: %w", err)
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		if _, owned := hopGateOwnedHeaders[http.CanonicalHeaderKey(key)]; owned {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(flushingResponseWriter{ResponseWriter: w}, resp.Body); err != nil {
		return fmt.Errorf("stream HTTP response body from yamux: %w", err)
	}
	return nil
}

type websocketForwarder interface {
	ForwardWebSocket(context.Context, logging.Logger, *http.Request, string, http.ResponseWriter) error
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func isExtendedConnectWebSocketRequest(r *http.Request) bool {
	return r.ProtoMajor >= 2 && r.Method == http.MethodConnect &&
		strings.EqualFold(r.Proto, "websocket")
}

func isSSERequest(r *http.Request) bool {
	for _, value := range r.Header.Values("Accept") {
		for _, mediaType := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(strings.SplitN(mediaType, ";", 2)[0]), "text/event-stream") {
				return true
			}
		}
	}
	return false
}

func (t *yamuxTunnelSession) ForwardWebSocket(ctx context.Context, logger logging.Logger, req *http.Request, serviceName string, w http.ResponseWriter) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := w.(http.Hijacker); !ok {
		return fmt.Errorf("websocket upgrade requires HTTP/1.1 hijacking")
	}
	stream, err := t.session.Open(ctx, tunnel.StreamMeta{
		Kind:    "websocket",
		Service: serviceName,
		Method:  req.Method,
		Path:    req.URL.RequestURI(),
		Host:    req.Host,
		Headers: req.Header,
	})
	if err != nil {
		return err
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	request := req.Clone(ctx)
	request.RequestURI = ""
	if err := request.Write(stream); err != nil {
		return fmt.Errorf("write WebSocket request to yamux stream: %w", err)
	}
	backendReader := bufio.NewReader(stream)
	backendResponse, err := http.ReadResponse(backendReader, req)
	if err != nil {
		return fmt.Errorf("read WebSocket handshake from yamux stream: %w", err)
	}
	if backendResponse.StatusCode != http.StatusSwitchingProtocols {
		defer backendResponse.Body.Close()
		w.WriteHeader(backendResponse.StatusCode)
		_, _ = io.Copy(w, backendResponse.Body)
		return fmt.Errorf("backend rejected WebSocket upgrade with status %d", backendResponse.StatusCode)
	}

	hijacker := w.(http.Hijacker)
	clientConn, clientRW, err := hijacker.Hijack()
	if err != nil {
		return fmt.Errorf("hijack public WebSocket connection: %w", err)
	}
	defer clientConn.Close()
	if err := backendResponse.Write(clientRW); err != nil {
		return fmt.Errorf("write WebSocket handshake to public client: %w", err)
	}
	if err := clientRW.Flush(); err != nil {
		return fmt.Errorf("flush WebSocket handshake: %w", err)
	}

	return relayConnections(clientRW.Reader, stream, clientConn, backendReader)
}

func (t *yamuxTunnelSession) ForwardExtendedConnect(ctx context.Context, logger logging.Logger, req *http.Request, serviceName string, w http.ResponseWriter) error {
	if ctx == nil {
		ctx = context.Background()
	}
	stream, err := t.session.Open(ctx, tunnel.StreamMeta{
		Kind:    "websocket",
		Service: serviceName,
		Method:  req.Method,
		Path:    req.URL.RequestURI(),
		Host:    req.Host,
		Headers: req.Header,
	})
	if err != nil {
		return err
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}

	request := req.Clone(ctx)
	request.Method = http.MethodGet
	request.RequestURI = ""
	request.Body = http.NoBody
	request.ContentLength = 0
	request.Header = request.Header.Clone()
	request.Header.Del(":protocol")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	if err := request.Write(stream); err != nil {
		return fmt.Errorf("write translated WebSocket request to yamux stream: %w", err)
	}

	backendReader := bufio.NewReader(stream)
	backendResponse, err := http.ReadResponse(backendReader, request)
	if err != nil {
		return fmt.Errorf("read translated WebSocket handshake from yamux stream: %w", err)
	}
	defer backendResponse.Body.Close()
	if backendResponse.StatusCode != http.StatusSwitchingProtocols {
		w.WriteHeader(http.StatusBadGateway)
		return fmt.Errorf("local WebSocket rejected Extended CONNECT with status %d", backendResponse.StatusCode)
	}

	for key, values := range backendResponse.Header {
		if _, owned := hopGateOwnedHeaders[http.CanonicalHeaderKey(key)]; owned {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	return relayConnections(req.Body, stream, flushingResponseWriter{ResponseWriter: w}, backendReader)
}

type flushingResponseWriter struct{ http.ResponseWriter }

func (w flushingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func relayConnections(clientReader io.Reader, stream io.Writer, clientWriter io.Writer, backend io.Reader) error {
	result := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, clientReader)
		result <- err
	}()
	go func() {
		_, err := io.Copy(clientWriter, backend)
		result <- err
	}()
	return <-result
}

func serveYamuxTunnel(ctx context.Context, address string, tlsConfig *tls.Config, logger logging.Logger, validator tunnel.DomainValidator) error {
	listener, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen for yamux tunnel: %w", err)
	}
	defer listener.Close()
	logger.Info("yamux tunnel listener started", logging.Fields{"addr": address})

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			logger.Error("yamux tunnel accept failed", logging.Fields{"error": err.Error()})
			continue
		}
		go handleYamuxTunnel(ctx, conn, logger, validator)
	}
}

func handleYamuxTunnel(ctx context.Context, conn net.Conn, logger logging.Logger, validator tunnel.DomainValidator) {
	session, err := tunnel.NewServer(conn)
	if err != nil {
		logger.Error("create yamux server session failed", logging.Fields{"error": err.Error()})
		return
	}
	defer session.Close()

	control, err := session.Accept(ctx)
	if err != nil {
		logger.Error("accept yamux control stream failed", logging.Fields{"error": err.Error()})
		return
	}
	defer control.Close()
	if control.Meta.Kind != "control" || strings.TrimSpace(control.Meta.Domain) == "" || strings.TrimSpace(control.Meta.Target) == "" {
		logger.Warn("invalid yamux control metadata", logging.Fields{"kind": control.Meta.Kind})
		return
	}
	apiKeys := control.Meta.Headers["X-HopGate-API-Key"]
	if len(apiKeys) == 0 || strings.TrimSpace(apiKeys[0]) == "" {
		logger.Warn("yamux control stream missing API key", logging.Fields{"domain": control.Meta.Domain})
		return
	}
	if validator != nil {
		if err := validator.ValidateDomainAPIKey(ctx, control.Meta.Domain, apiKeys[0]); err != nil {
			logger.Warn("yamux tunnel authentication failed", logging.Fields{"domain": control.Meta.Domain, "error": err.Error()})
			return
		}
	}

	tunnelSession := &yamuxTunnelSession{session: session, logger: logger.With(logging.Fields{"domain": control.Meta.Domain})}
	domain := registerTunnelForDomain(control.Meta.Domain, tunnelSession, logger)
	defer unregisterTunnelForDomain(domain, tunnelSession, logger)
	logger.Info("yamux tunnel authenticated", logging.Fields{"domain": domain, "local_target": control.Meta.Target})

	// The server opens HTTP streams. The client opens only the control stream,
	// so poll the session state rather than consuming the server's own streams.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for !session.IsClosed() {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
