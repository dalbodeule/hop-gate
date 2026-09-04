package main

import (
	"context"
	"flag"
	"os"
	"strings"

	"github.com/dalbodeule/hop-gate/internal/config"
	"github.com/dalbodeule/hop-gate/internal/logging"
)

var version = "dev"

func getEnvOrPanic(logger logging.Logger, key string) string {
	value, exists := os.LookupEnv(key)
	if !exists || strings.TrimSpace(value) == "" {
		logger.Error("missing required environment variable", logging.Fields{"env": key})
		os.Exit(1)
	}
	return value
}

func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func main() {
	logger := logging.NewStdJSONLogger("client")
	envCfg, err := config.LoadClientConfigFromEnv()
	if err != nil {
		logger.Error("failed to load client config from env", logging.Fields{"error": err.Error()})
		os.Exit(1)
	}

	serverAddrEnv := getEnvOrPanic(logger, "HOP_CLIENT_SERVER_ADDR")
	domainEnv := getEnvOrPanic(logger, "HOP_CLIENT_DOMAIN")
	apiKeyEnv := getEnvOrPanic(logger, "HOP_CLIENT_API_KEY")
	localTargetEnv := getEnvOrPanic(logger, "HOP_CLIENT_LOCAL_TARGET")
	debugEnv := getEnvOrPanic(logger, "HOP_CLIENT_DEBUG")
	if debugEnv != "true" && debugEnv != "false" {
		logger.Error("invalid value for HOP_CLIENT_DEBUG; must be 'true' or 'false'", logging.Fields{"value": debugEnv})
		os.Exit(1)
	}

	serverAddrFlag := flag.String("server-addr", "", "HopGate yamux server address (host:port)")
	domainFlag := flag.String("domain", "", "registered domain")
	apiKeyFlag := flag.String("api-key", "", "client API key for the domain")
	localTargetFlag := flag.String("local-target", "", "local HTTP target (host:port)")
	flag.Parse()

	finalCfg := &config.ClientConfig{
		ServerAddr:   firstNonEmpty(*serverAddrFlag, envCfg.ServerAddr),
		Domain:       firstNonEmpty(*domainFlag, envCfg.Domain),
		ClientAPIKey: firstNonEmpty(*apiKeyFlag, envCfg.ClientAPIKey),
		LocalTarget:  firstNonEmpty(*localTargetFlag, envCfg.LocalTarget),
		Debug:        envCfg.Debug,
		Logging:      envCfg.Logging,
	}
	if finalCfg.ServerAddr == "" || finalCfg.Domain == "" || finalCfg.ClientAPIKey == "" || finalCfg.LocalTarget == "" {
		logger.Error("client config is incomplete", logging.Fields{
			"server_addr":  finalCfg.ServerAddr != "",
			"domain":       finalCfg.Domain != "",
			"api_key":      finalCfg.ClientAPIKey != "",
			"local_target": finalCfg.LocalTarget != "",
		})
		os.Exit(1)
	}

	logger.Info("hop-gate yamux client starting", logging.Fields{
		"version":             version,
		"server_addr":         serverAddrEnv,
		"domain":              domainEnv,
		"client_api_key_mask": maskAPIKey(apiKeyEnv),
		"local_target":        localTargetEnv,
		"debug":               finalCfg.Debug,
	})

	if err := runYamuxTunnelClient(context.Background(), logger, finalCfg); err != nil {
		logger.Error("yamux tunnel client exited with error", logging.Fields{"error": err.Error()})
		os.Exit(1)
	}
}
