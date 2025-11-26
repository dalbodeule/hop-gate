package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dalbodeule/hop-gate/internal/logging"
	webroot2 "github.com/go-acme/lego/v4/providers/http/webroot"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// Manager 는 ACME 기반 인증서 관리를 추상화합니다. (ko)
// Manager abstracts ACME-based certificate management. (en)
type Manager interface {
	// TLSConfig 는 HTTPS 및 DTLS 서버에 주입할 tls.Config 를 반환합니다. (ko)
	// TLSConfig returns a tls.Config to be used by HTTPS and DTLS servers. (en)
	TLSConfig() *tls.Config
}

// legoManager 는 go-acme/lego 를 사용해 도메인별 TLS 인증서를 관리합니다. (ko)
// legoManager manages per-domain TLS certificates using go-acme/lego. (en)
type legoManager struct {
	cacheDir  string
	domains   []string
	logger    logging.Logger
	tlsConfig *tls.Config
}

func (m *legoManager) TLSConfig() *tls.Config {
	return m.tlsConfig
}

// getCertificate 는 ClientHello 의 SNI 를 기반으로 디스크에서 최신 인증서를 로드합니다. (ko)
// getCertificate loads the latest certificate from disk based on the SNI in ClientHello. (en)
func (m *legoManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := strings.ToLower(strings.TrimSpace(hello.ServerName))
	if domain == "" && len(m.domains) > 0 {
		// SNI 가 비어있으면 첫 번째 도메인으로 fallback. (ko)
		// If SNI is empty, fall back to the first configured domain. (en)
		domain = m.domains[0]
	}
	if domain == "" {
		return nil, fmt.Errorf("no server name (SNI) provided and no default domain configured")
	}

	// 정규화된 도메인을 기준으로 cert/key 경로 구성. (ko)
	// Build cert/key paths based on normalized domain. (en)
	certPath := filepath.Join(m.cacheDir, domain+".crt")
	keyPath := filepath.Join(m.cacheDir, domain+".key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		m.logger.Error("failed to load certificate for domain", logging.Fields{
			"domain":    domain,
			"cert_path": certPath,
			"key_path":  keyPath,
			"error":     err.Error(),
		})
		// 도메인이 리스트에 있고, 첫 번째 도메인과 다르면 첫 번째 도메인으로 한 번 더 시도. (ko)
		// If this is not the first domain, attempt to fall back to the first domain. (en)
		if len(m.domains) > 0 && domain != m.domains[0] {
			fallback := m.domains[0]
			fCertPath := filepath.Join(m.cacheDir, fallback+".crt")
			fKeyPath := filepath.Join(m.cacheDir, fallback+".key")
			fCert, fErr := tls.LoadX509KeyPair(fCertPath, fKeyPath)
			if fErr == nil {
				m.logger.Warn("falling back to default certificate for domain", logging.Fields{
					"requested_domain": domain,
					"fallback_domain":  fallback,
				})
				return &fCert, nil
			}
			m.logger.Error("failed to load fallback certificate", logging.Fields{
				"fallback_domain": fallback,
				"cert_path":       fCertPath,
				"key_path":        fKeyPath,
				"error":           fErr.Error(),
			})
		}
		return nil, err
	}

	return &cert, nil
}

// NewDummyManager 는 초기 개발 단계를 위한 더미 구현입니다. (ko)
// NewDummyManager is a placeholder manager for early development. (en)
func NewDummyManager() Manager {
	return &dummyManager{}
}

type dummyManager struct{}

func (d *dummyManager) TLSConfig() *tls.Config {
	return &tls.Config{}
}

// legoUser implements lego.User.
type legoUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration,omitempty"`
	KeyPEM       []byte                 `json:"key_pem,omitempty"`
	key          crypto.PrivateKey      // not marshaled, derived from KeyPEM
}

func (u *legoUser) GetEmail() string {
	return u.Email
}

func (u *legoUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *legoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// NewLegoManagerFromEnv 는 환경변수와 도메인 목록을 기반으로 lego 기반 ACME 매니저를 생성합니다. (ko)
// NewLegoManagerFromEnv creates an ACME manager based on environment variables and a list of domains. (en)
//
// Required env:
//   - HOP_ACME_EMAIL        : account email for Let's Encrypt
//   - HOP_ACME_CACHE_DIR    : directory to store certificates and lego account data
//
// Optional env:
//   - HOP_ACME_CA_DIR       : ACME directory URL (default: Let's Encrypt production)
//   - HOP_ACME_USE_STAGING  : if true, use Let's Encrypt staging CA instead of production
//   - HOP_ACME_EXPECT_IPS   : comma-separated list of IPs that domains must resolve to (via 1.1.1.1 DNS)
func NewLegoManagerFromEnv(ctx context.Context, logger logging.Logger, domains []string) (Manager, error) {
	email := strings.TrimSpace(os.Getenv("HOP_ACME_EMAIL"))
	cacheDir := strings.TrimSpace(os.Getenv("HOP_ACME_CACHE_DIR"))
	caDir := strings.TrimSpace(os.Getenv("HOP_ACME_CA_DIR"))
	useStaging := getEnvBool("HOP_ACME_USE_STAGING", false)
	expectedIPs := parseCSVEnv("HOP_ACME_EXPECT_IPS")

	if email == "" {
		return nil, fmt.Errorf("HOP_ACME_EMAIL is required")
	}
	if cacheDir == "" {
		return nil, fmt.Errorf("HOP_ACME_CACHE_DIR is required")
	}
	if caDir == "" {
		if useStaging {
			caDir = lego.LEDirectoryStaging
		} else {
			caDir = lego.LEDirectoryProduction
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required for ACME")
	}

	// Normalize and deduplicate domain list.
	domainSet := make(map[string]struct{})
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			continue
		}
		domainSet[d] = struct{}{}
	}
	if len(domainSet) == 0 {
		return nil, fmt.Errorf("no valid domains after normalization")
	}
	var uniqDomains []string
	for d := range domainSet {
		uniqDomains = append(uniqDomains, d)
	}

	logger.Info("acme lego manager initializing", logging.Fields{
		"email":       email,
		"cache_dir":   cacheDir,
		"ca_dir":      caDir,
		"use_staging": useStaging,
		"domains":     uniqDomains,
	})

	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create acme cache dir: %w", err)
	}

	// 1. DNS 확인: 1.1.1.1 DNS를 사용해 도메인이 예상 IP에 연결되어 있는지 체크. (ko)
	// 1. DNS check: use 1.1.1.1 resolver to ensure domains resolve to expected IPs. (en)
	if err := verifyDomainsResolve(ctx, logger, uniqDomains, expectedIPs); err != nil {
		return nil, err
	}

	// 2. lego user 로드/생성. (ko)
	// 2. Load or create lego user. (en)
	user, err := loadOrCreateUser(cacheDir, email)
	if err != nil {
		return nil, fmt.Errorf("load/create lego user: %w", err)
	}

	// 3. lego config & client 생성. (ko)
	// 3. Build lego config & client. (en)
	cfg := lego.NewConfig(user)
	cfg.CADirURL = caDir
	cfg.Certificate = lego.CertificateConfig{
		KeyType: certKeyType(),
	}

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new lego client: %w", err)
	}

	// Account registration (if not yet registered).
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("lego registration: %w", err)
		}
		user.Registration = reg
		if err := saveUser(cacheDir, user); err != nil {
			return nil, fmt.Errorf("save lego user after registration: %w", err)
		}
	}

	// 4. HTTP-01 챌린지 프로바이더 설정 (webroot 방식). (ko)
	// 4. Configure HTTP-01 challenge provider using webroot. (en)
	//
	// go-acme/lego 가 자체적으로 포트를 바인딩하지 않고,
	// 지정된 디렉터리(HOP_ACME_WEBROOT)에 챌린지 파일을 생성하도록 합니다.
	// 메인 HTTP 서버는 /.well-known/acme-challenge/* 요청을 이 디렉터리에서 서빙해야 합니다.
	//
	// Using webroot avoids lego binding its own HTTP server; instead, it writes the
	// challenge files into HOP_ACME_WEBROOT and the main HTTP server must serve
	// /.well-known/acme-challenge/* from that directory.
	webroot := strings.TrimSpace(os.Getenv("HOP_ACME_WEBROOT"))
	if webroot == "" {
		return nil, fmt.Errorf("HOP_ACME_WEBROOT is required when using ACME webroot mode")
	}
	if err := os.MkdirAll(webroot, 0o755); err != nil {
		return nil, fmt.Errorf("create acme webroot dir: %w", err)
	}

	provider, err := webroot2.NewHTTPProvider(webroot)
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, fmt.Errorf("set http-01 filesystem provider: %w", err)
	}

	// 5. 도메인별 인증서 확보/갱신 및 캐시 디렉터리에 저장. (ko)
	// 5. Ensure certificates per domain and store them in cache directory. (en)
	for _, domain := range uniqDomains {
		if _, err := ensureCertForDomain(ctx, logger, client, cacheDir, domain); err != nil {
			return nil, fmt.Errorf("ensure cert for domain %s: %w", domain, err)
		}
	}

	// 6. tls.Config 생성 (GetCertificate 기반). (ko)
	// 6. Build tls.Config using GetCertificate callback. (en)
	mgr := &legoManager{
		cacheDir: cacheDir,
		domains:  uniqDomains,
		logger:   logger.With(logging.Fields{"component": "acme_lego_manager"}),
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// 각 핸드셰이크마다 최신 인증서를 디스크에서 읽어오도록 합니다.
		// Load from disk on each handshake so newly issued certificates are picked up
		// without restarting the server.
		GetCertificate: mgr.getCertificate,
	}
	mgr.tlsConfig = tlsCfg

	return mgr, nil
}

// verifyDomainsResolve checks that each domain resolves via 1.1.1.1 and,
// if expectedIPs is non-empty, that at least one of the resolved IPs matches.
func verifyDomainsResolve(ctx context.Context, logger logging.Logger, domains, expectedIPs []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}

	expectedSet := make(map[string]struct{})
	for _, ip := range expectedIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		expectedSet[ip] = struct{}{}
	}

	for _, domain := range domains {
		ips, err := resolver.LookupHost(ctx, domain)
		if err != nil {
			logger.Error("acme dns resolution failed", logging.Fields{
				"domain": domain,
				"error":  err.Error(),
			})
			return fmt.Errorf("dns resolution failed for %s: %w", domain, err)
		}
		logger.Info("acme dns resolution", logging.Fields{
			"domain": domain,
			"ips":    ips,
		})

		if len(expectedSet) == 0 {
			// No expected IPs configured; DNS resolution success is enough.
			continue
		}

		match := false
		for _, ip := range ips {
			if _, ok := expectedSet[ip]; ok {
				match = true
				break
			}
		}
		if !match {
			return fmt.Errorf("dns resolution for %s did not match any expected IPs", domain)
		}
	}

	return nil
}

// ensureCertForDomain loads an existing certificate for the domain from cacheDir,
// checks its expiration, and renews or obtains a new certificate via lego if needed.
func ensureCertForDomain(ctx context.Context, logger logging.Logger, client *lego.Client, cacheDir, domain string) (tls.Certificate, error) {
	certPath := filepath.Join(cacheDir, domain+".crt")
	keyPath := filepath.Join(cacheDir, domain+".key")

	// Try to load an existing certificate.
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			existing, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil {
				// Check expiration.
				leaf, err := parseLeaf(&existing)
				if err == nil {
					// If the cert is valid for more than 30 days, reuse.
					if time.Until(leaf.NotAfter) > 30*24*time.Hour {
						logger.Info("using existing certificate from cache", logging.Fields{
							"domain":     domain,
							"not_after":  leaf.NotAfter,
							"cache_path": certPath,
						})
						return existing, nil
					}
					logger.Info("existing certificate is close to expiry, will renew", logging.Fields{
						"domain":    domain,
						"not_after": leaf.NotAfter,
					})
				}
			}
		}
	}

	// No valid certificate found; obtain a new one via ACME.
	logger.Info("requesting new certificate via ACME", logging.Fields{
		"domain": domain,
	})

	req := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certRes, err := client.Certificate.Obtain(req)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("obtain certificate: %w", err)
	}

	if err := os.WriteFile(certPath, certRes.Certificate, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write cert file: %w", err)
	}
	if err := os.WriteFile(keyPath, certRes.PrivateKey, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write key file: %w", err)
	}

	logger.Info("stored new certificate", logging.Fields{
		"domain":    domain,
		"cert_path": certPath,
		"key_path":  keyPath,
		"not_after": time.Now().Add(90 * 24 * time.Hour), // approximate
	})

	return tls.LoadX509KeyPair(certPath, keyPath)
}

func parseLeaf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("empty certificate")
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

// uniqueNamesFromCert returns a list of DNS names / CN from the certificate.
func uniqueNamesFromCert(cert *tls.Certificate) []string {
	leaf, err := parseLeaf(cert)
	if err != nil {
		return nil
	}
	names := make(map[string]struct{})
	if leaf.Subject.CommonName != "" {
		names[strings.ToLower(leaf.Subject.CommonName)] = struct{}{}
	}
	for _, n := range leaf.DNSNames {
		names[strings.ToLower(n)] = struct{}{}
	}
	var out []string
	for n := range names {
		out = append(out, n)
	}
	return out
}

// loadOrCreateUser loads an existing lego user from cacheDir or creates a new one.
func loadOrCreateUser(cacheDir, email string) (*legoUser, error) {
	userPath := filepath.Join(cacheDir, "lego_user.json")

	if data, err := os.ReadFile(userPath); err == nil {
		var u legoUser
		if err := json.Unmarshal(data, &u); err == nil && u.Email == email && len(u.KeyPEM) > 0 {
			key, err := x509.ParseECPrivateKey(u.KeyPEM)
			if err == nil {
				u.key = key
				return &u, nil
			}
		}
	}

	// Create new user with a new key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal ecdsa key: %w", err)
	}

	u := &legoUser{
		Email:  email,
		KeyPEM: keyBytes,
		key:    priv,
	}
	if err := saveUser(cacheDir, u); err != nil {
		return nil, err
	}
	return u, nil
}

// saveUser persists the lego user to disk.
func saveUser(cacheDir string, u *legoUser) error {
	userPath := filepath.Join(cacheDir, "lego_user.json")
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal lego user: %w", err)
	}
	if err := os.WriteFile(userPath, data, 0o600); err != nil {
		return fmt.Errorf("write lego user file: %w", err)
	}
	return nil
}

// certKeyType returns the preferred key type for new certificates.
func certKeyType() certcrypto.KeyType {
	return certcrypto.EC256
}

// randReader wraps crypto/rand.Reader so it can be swapped in tests if needed.
type randReaderType struct{}

func (randReaderType) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

var randReader = randReaderType{}

// getEnvBool is a local helper to read boolean env vars.
func getEnvBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

// parseCSVEnv is a local helper to parse comma-separated env vars into []string.
func parseCSVEnv(key string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
