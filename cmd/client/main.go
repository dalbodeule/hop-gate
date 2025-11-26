package main

import (
	"github.com/dalbodeule/hop-gate/internal/logging"
)

func main() {
	logger := logging.NewStdJSONLogger("client")
	logger.Info("hop-gate client starting", logging.Fields{
		"stack": "prometheus-loki-grafana",
	})
	// TODO: load configuration from internal/config
	// TODO: initialize logging details (instance, env, version) via logger.With(...)
	// TODO: establish DTLS connection to server via internal/dtls
	// TODO: start request handling loop using internal/proxy and internal/protocol
}
