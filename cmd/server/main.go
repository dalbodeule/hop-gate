package main

import (
	"github.com/dalbodeule/hop-gate/internal/logging"
)

func main() {
	logger := logging.NewStdJSONLogger("server")
	logger.Info("hop-gate server starting", logging.Fields{
		"stack": "prometheus-loki-grafana",
	})
	// TODO: load configuration from internal/config
	// TODO: initialize logging details (instance, env, version) via logger.With(...)
	// TODO: initialize ACME manager from internal/acme
	// TODO: start HTTP/HTTPS listeners and DTLS listener
}
