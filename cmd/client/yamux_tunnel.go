package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dalbodeule/hop-gate/internal/config"
	"github.com/dalbodeule/hop-gate/internal/logging"
	"github.com/dalbodeule/hop-gate/internal/tunnel"
	"github.com/gorilla/websocket"
)

func runYamuxTunnelClient(ctx context.Context, logger logging.Logger, cfg *config.ClientConfig) error {
	host := cfg.ServerAddr
	if h, _, err := net.SplitHostPort(cfg.ServerAddr); err == nil {
		host = h
	}
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if cfg.Debug {
		tlsConfig.InsecureSkipVerify = true
	} else if roots, err := x509.SystemCertPool(); err == nil {
		tlsConfig.RootCAs = roots
	}

	session, err := tunnel.DialTLS(ctx, cfg.ServerAddr, tlsConfig)
	if err != nil {
		return err
	}
	defer session.Close()

	control, err := session.Open(ctx, tunnel.StreamMeta{
		Kind:   "control",
		Domain: cfg.Domain,
		Target: cfg.LocalTarget,
		Headers: map[string][]string{
			"X-HopGate-API-Key": {cfg.ClientAPIKey},
		},
	})
	if err != nil {
		return fmt.Errorf("open yamux control stream: %w", err)
	}
	_ = control.Close()

	localBase, err := url.Parse("http://" + cfg.LocalTarget)
	if err != nil {
		return fmt.Errorf("parse local target: %w", err)
	}
	client := &http.Client{Timeout: 0, Transport: &http.Transport{
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
	}}
	logger.Info("yamux tunnel client connected", logging.Fields{"server_addr": cfg.ServerAddr, "domain": cfg.Domain})

	for {
		stream, err := session.Accept(ctx)
		if err != nil {
			return err
		}
		go handleYamuxHTTPStream(ctx, stream, client, localBase, logger)
	}
}

func handleYamuxHTTPStream(ctx context.Context, stream *tunnel.Stream, client *http.Client, localBase *url.URL, logger logging.Logger) {
	defer stream.Close()
	if stream.Meta.Kind == "websocket" {
		handleYamuxWebSocketStream(ctx, stream, localBase, logger)
		return
	}
	if stream.Meta.Kind != "http" {
		logger.Warn("unsupported yamux stream kind", logging.Fields{"kind": stream.Meta.Kind})
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(stream))
	if err != nil {
		logger.Warn("read HTTP request from yamux stream failed", logging.Fields{"error": err.Error()})
		return
	}
	request.URL.Scheme = localBase.Scheme
	request.URL.Host = localBase.Host
	request.RequestURI = ""
	response, err := client.Do(request)
	if err != nil {
		logger.Warn("forward HTTP request to local target failed", logging.Fields{"error": err.Error()})
		failure := &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
			Body:       http.NoBody,
			Request:    request,
		}
		if writeErr := failure.Write(stream); writeErr != nil {
			logger.Warn("write local HTTP failure to yamux stream failed", logging.Fields{"error": writeErr.Error()})
		}
		return
	}
	defer response.Body.Close()
	if err := writeHTTPResponse(stream, response); err != nil {
		logger.Warn("write local HTTP response to yamux stream failed", logging.Fields{"error": err.Error()})
	}
}

func writeHTTPResponse(stream io.Writer, response *http.Response) error {
	return response.Write(stream)
}

func handleYamuxWebSocketStream(ctx context.Context, stream *tunnel.Stream, localBase *url.URL, logger logging.Logger) {
	request, err := http.ReadRequest(bufio.NewReader(stream))
	if err != nil {
		logger.Warn("read WebSocket request from yamux stream failed", logging.Fields{"error": err.Error()})
		return
	}
	request.URL.Scheme = "ws"
	request.URL.Host = localBase.Host
	request.RequestURI = ""

	header := make(http.Header)
	var subprotocols []string
	for key, values := range request.Header {
		switch http.CanonicalHeaderKey(key) {
		case "Connection", "Upgrade", "Sec-Websocket-Key", "Sec-Websocket-Version", "Sec-Websocket-Extensions":
			continue
		case "Sec-Websocket-Protocol":
			for _, value := range values {
				for _, protocol := range strings.Split(value, ",") {
					if strings.TrimSpace(protocol) != "" {
						subprotocols = append(subprotocols, strings.TrimSpace(protocol))
					}
				}
			}
		default:
			header[key] = append([]string(nil), values...)
		}
	}
	dialer := websocket.Dialer{Subprotocols: subprotocols, HandshakeTimeout: 10 * time.Second}
	backend, response, err := dialer.DialContext(ctx, request.URL.String(), header)
	if err != nil {
		logger.Warn("dial local WebSocket failed", logging.Fields{"error": err.Error()})
		failure := &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
			Body:       http.NoBody,
		}
		_ = failure.Write(stream)
		return
	}
	defer backend.Close()
	if err := response.Write(stream); err != nil {
		logger.Warn("write WebSocket handshake to server failed", logging.Fields{"error": err.Error()})
		return
	}

	backendConn := backend.UnderlyingConn()
	result := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, backendConn)
		result <- err
	}()
	go func() {
		_, err := io.Copy(backendConn, stream)
		result <- err
	}()
	<-result
}
