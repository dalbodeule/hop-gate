package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dalbodeule/hop-gate/internal/logging"
)

// Handler 는 /api/v1/admin 관리 plane HTTP 엔드포인트를 제공합니다.
type Handler struct {
	Logger      logging.Logger
	AdminAPIKey string
	Service     DomainService
}

// NewHandler 는 새로운 Handler 를 생성합니다.
func NewHandler(logger logging.Logger, adminAPIKey string, svc DomainService) *Handler {
	return &Handler{
		Logger:      logger.With(logging.Fields{"component": "admin_api"}),
		AdminAPIKey: strings.TrimSpace(adminAPIKey),
		Service:     svc,
	}
}

// RegisterRoutes 는 전달받은 mux 에 관리 API 라우트를 등록합니다.
//   - POST /api/v1/admin/domains/register
//   - POST /api/v1/admin/domains/unregister
//   - GET  /api/v1/admin/domains/exists
//   - GET  /api/v1/admin/domains/status
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/api/v1/admin/domains/register", h.authMiddleware(http.HandlerFunc(h.handleDomainRegister)))
	mux.Handle("/api/v1/admin/domains/unregister", h.authMiddleware(http.HandlerFunc(h.handleDomainUnregister)))
	mux.Handle("/api/v1/admin/domains/exists", h.authMiddleware(http.HandlerFunc(h.handleDomainExists)))
	mux.Handle("/api/v1/admin/domains/status", h.authMiddleware(http.HandlerFunc(h.handleDomainStatus)))
}

// authMiddleware 는 Authorization: Bearer {ADMIN_API_KEY} 헤더를 검증합니다.
func (h *Handler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.authenticate(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"error":   "unauthorized",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) authenticate(r *http.Request) bool {
	if h.AdminAPIKey == "" {
		// Admin API 키가 설정되지 않았다면 모든 요청을 거부
		return false
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	return token == h.AdminAPIKey
}

type domainRegisterRequest struct {
	Domain string `json:"domain"`
	Memo   string `json:"memo"`
}

type domainRegisterResponse struct {
	ClientAPIKey string `json:"client_api_key,omitempty"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

func (h *Handler) handleDomainRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, r)
		return
	}

	var req domainRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.Warn("invalid register request body", logging.Fields{"error": err.Error()})
		h.writeJSON(w, http.StatusBadRequest, domainRegisterResponse{
			Success: false,
			Error:   "invalid request body",
		})
		return
	}
	req.Domain = strings.TrimSpace(req.Domain)

	if req.Domain == "" {
		h.writeJSON(w, http.StatusBadRequest, domainRegisterResponse{
			Success: false,
			Error:   "domain is required",
		})
		return
	}

	clientKey, err := h.Service.RegisterDomain(r.Context(), req.Domain, req.Memo)
	if err != nil {
		h.Logger.Error("failed to register domain", logging.Fields{
			"domain": req.Domain,
			"error":  err.Error(),
		})
		h.writeJSON(w, http.StatusInternalServerError, domainRegisterResponse{
			Success: false,
			Error:   "internal error",
		})
		return
	}

	h.writeJSON(w, http.StatusOK, domainRegisterResponse{
		Success:      true,
		ClientAPIKey: clientKey,
	})
}

type domainUnregisterRequest struct {
	Domain       string `json:"domain"`
	ClientAPIKey string `json:"client_api_key"`
}

type domainUnregisterResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type domainExistsResponse struct {
	Success bool   `json:"success"`
	Exists  bool   `json:"exists"`
	Error   string `json:"error,omitempty"`
}

type domainStatusResponse struct {
	Success   bool      `json:"success"`
	Exists    bool      `json:"exists"`
	Domain    string    `json:"domain,omitempty"`
	Memo      string    `json:"memo,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

func (h *Handler) handleDomainUnregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w, r)
		return
	}

	var req domainUnregisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.Warn("invalid unregister request body", logging.Fields{"error": err.Error()})
		h.writeJSON(w, http.StatusBadRequest, domainUnregisterResponse{
			Success: false,
			Error:   "invalid request body",
		})
		return
	}
	req.Domain = strings.TrimSpace(req.Domain)
	req.ClientAPIKey = strings.TrimSpace(req.ClientAPIKey)

	if req.Domain == "" || req.ClientAPIKey == "" {
		h.writeJSON(w, http.StatusBadRequest, domainUnregisterResponse{
			Success: false,
			Error:   "domain and client_api_key are required",
		})
		return
	}

	if err := h.Service.UnregisterDomain(r.Context(), req.Domain, req.ClientAPIKey); err != nil {
		h.Logger.Error("failed to unregister domain", logging.Fields{
			"domain":         req.Domain,
			"client_api_key": "***",
			"error":          err.Error(),
		})
		h.writeJSON(w, http.StatusInternalServerError, domainUnregisterResponse{
			Success: false,
			Error:   "internal error",
		})
		return
	}

	h.writeJSON(w, http.StatusOK, domainUnregisterResponse{
		Success: true,
	})
}

func (h *Handler) handleDomainExists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w, r)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		h.writeJSON(w, http.StatusBadRequest, domainExistsResponse{
			Success: false,
			Error:   "domain is required",
		})
		return
	}

	exists, err := h.Service.IsDomainRegistered(r.Context(), domain)
	if err != nil {
		h.Logger.Error("failed to check domain existence", logging.Fields{
			"domain": domain,
			"error":  err.Error(),
		})
		h.writeJSON(w, http.StatusInternalServerError, domainExistsResponse{
			Success: false,
			Error:   "internal error",
		})
		return
	}

	h.writeJSON(w, http.StatusOK, domainExistsResponse{
		Success: true,
		Exists:  exists,
	})
}

func (h *Handler) handleDomainStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w, r)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		h.writeJSON(w, http.StatusBadRequest, domainStatusResponse{
			Success: false,
			Error:   "domain is required",
		})
		return
	}

	row, err := h.Service.GetDomain(r.Context(), domain)
	if err != nil {
		if err == ErrDomainNotFound {
			h.writeJSON(w, http.StatusOK, domainStatusResponse{
				Success: true,
				Exists:  false,
			})
			return
		}

		h.Logger.Error("failed to get domain status", logging.Fields{
			"domain": domain,
			"error":  err.Error(),
		})
		h.writeJSON(w, http.StatusInternalServerError, domainStatusResponse{
			Success: false,
			Error:   "internal error",
		})
		return
	}

	h.writeJSON(w, http.StatusOK, domainStatusResponse{
		Success:   true,
		Exists:    true,
		Domain:    row.Domain,
		Memo:      row.Memo,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	})
}

func (h *Handler) writeMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
		"success": false,
		"error":   "method not allowed",
	})
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.Logger.Error("failed to write json response", logging.Fields{"error": err.Error()})
	}
}
