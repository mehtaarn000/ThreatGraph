package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxRequestBytes = 16 * 1024

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Handler struct {
	dnsScorer      DNSScorer
	dnsPredictions DNSPredictionRepository
	dns            DNSService
	scorer         Scorer
	repo           Repository
	logger         *slog.Logger
}

func NewHandler(scorer Scorer, repo Repository, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{scorer: scorer, repo: repo, logger: logger}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /readyz", h.ready)
	mux.HandleFunc("POST /v1/analyses", h.createAnalysis)
	mux.HandleFunc("GET /v1/analyses/{id}", h.getAnalysis)
	if h.dns != nil {
		if h.dnsScorer != nil && h.dnsPredictions != nil {
			mux.HandleFunc("POST /v1/domains/{domain}/dns/predictions", h.createDNSPrediction)
			mux.HandleFunc("GET /v1/domains/{domain}/dns/predictions", h.listDNSPredictions)
		}
		mux.HandleFunc("POST /v1/domains/{domain}/dns", h.enrichDNS)
		mux.HandleFunc("GET /v1/domains/{domain}/dns", h.latestDNS)
		mux.HandleFunc("GET /v1/domains/{domain}/dns/history", h.dnsHistory)
		mux.HandleFunc("POST /v1/analyses/{id}/dns", h.enrichDNS)
	}
	return securityHeaders(h.accessLog(mux))
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (h *Handler) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		h.logger.Info("http request", "method", r.Method, "path", r.URL.Path, "status", recorder.status, "duration_ms", time.Since(started).Milliseconds())
	})
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.repo.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "The database is not ready.")
		return
	}
	if err := h.scorer.Ready(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "model_service_unavailable", "The model service is not ready.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (h *Handler) createAnalysis(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request CreateAnalysisRequest
	if err := decoder.Decode(&request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "The request body is too large.")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json", "The request body must be valid JSON with supported fields.")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "The request body must contain one JSON object.")
		return
	}
	if message := validateRequest(request); message != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_analysis", message)
		return
	}
	request.CandidateURL = strings.TrimSpace(request.CandidateURL)
	request.BrandName = strings.TrimSpace(request.BrandName)
	request.BrandDomain = strings.TrimSpace(request.BrandDomain)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	result, err := h.scorer.Score(ctx, request)
	if err != nil {
		h.logger.Error("model scoring request failed", "error", err)
		writeError(w, http.StatusBadGateway, "model_service_error", "The model service could not score this domain.")
		return
	}
	if math.IsNaN(result.ImpersonationScore) || math.IsInf(result.ImpersonationScore, 0) || result.ImpersonationScore < 0 || result.ImpersonationScore > 1 {
		h.logger.Error("model returned an invalid score", "score", result.ImpersonationScore)
		writeError(w, http.StatusBadGateway, "invalid_model_response", "The model service returned an invalid score.")
		return
	}

	analysis, err := h.repo.Create(ctx, request, result)
	if err != nil {
		h.logger.Error("could not save analysis", "error", err)
		writeError(w, http.StatusInternalServerError, "persistence_error", "The analysis could not be saved.")
		return
	}
	writeJSON(w, http.StatusCreated, analysis)
}

func (h *Handler) getAnalysis(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if !uuidPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid_id", "The analysis ID is invalid.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	analysis, err := h.repo.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "analysis_not_found", "No analysis exists with that ID.")
		return
	}
	if err != nil {
		h.logger.Error("could not load analysis", "error", err)
		writeError(w, http.StatusInternalServerError, "persistence_error", "The analysis could not be loaded.")
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func validateRequest(request CreateAnalysisRequest) string {
	candidateURL := strings.TrimSpace(request.CandidateURL)
	brandName := strings.TrimSpace(request.BrandName)
	brandDomain := strings.TrimSpace(request.BrandDomain)
	if candidateURL == "" || brandName == "" || brandDomain == "" {
		return "candidate_url, brand_name, and brand_domain are required."
	}
	if len(candidateURL) > 4096 || len(brandName) > 200 || len(brandDomain) > 253 {
		return "A field exceeds its maximum allowed length."
	}
	parsed, err := url.ParseRequestURI(candidateURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "candidate_url must be an absolute HTTP or HTTPS URL."
	}
	brandURL := brandDomain
	if !strings.Contains(brandURL, "://") {
		brandURL = "https://" + brandURL
	}
	parsedBrand, err := url.ParseRequestURI(brandURL)
	if err != nil || (parsedBrand.Scheme != "http" && parsedBrand.Scheme != "https") || parsedBrand.Hostname() == "" {
		return "brand_domain must be a valid domain or HTTP(S) URL."
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{Error: APIError{Code: code, Message: message}})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
