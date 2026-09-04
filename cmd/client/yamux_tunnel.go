package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/dalbodeule/hop-gate/internal/config"
	"github.com/dalbodeule/hop-gate/internal/logging"
	"github.com/dalbodeule/hop-gate/internal/tunnel"
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
		go handleYamuxHTTPStream(stream, client, localBase, logger)
	}
}

func handleYamuxHTTPStream(stream *tunnel.Stream, client *http.Client, localBase *url.URL, logger logging.Logger) {
	defer stream.Close()
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
	if err := response.Write(stream); err != nil {
		logger.Warn("write local HTTP response to yamux stream failed", logging.Fields{"error": err.Error()})
	}
}
