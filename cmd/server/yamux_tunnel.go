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

func (t *yamuxTunnelSession) ForwardHTTP(ctx context.Context, logger logging.Logger, req *http.Request, serviceName string) (*tunnel.Response, error) {
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
		return nil, err
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}

	request := req.Clone(ctx)
	request.RequestURI = ""
	if err := request.Write(stream); err != nil {
		return nil, fmt.Errorf("write HTTP request to yamux stream: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		return nil, fmt.Errorf("read HTTP response from yamux stream: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read HTTP response body from yamux stream: %w", err)
	}
	result := &tunnel.Response{
		RequestID: "yamux",
		Status:    resp.StatusCode,
		Header:    make(map[string][]string, len(resp.Header)),
		Body:      body,
	}
	for key, values := range resp.Header {
		result.Header[key] = append([]string(nil), values...)
	}
	return result, nil
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
