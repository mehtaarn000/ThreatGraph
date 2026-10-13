package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"threatgraph/backend/internal/enrichment"
)

type DNSService interface {
	Enrich(context.Context, string) (enrichment.Result, error)
	Latest(context.Context, string) (enrichment.Snapshot, error)
	History(context.Context, string, int) ([]enrichment.Snapshot, error)
}

// WithDNS enables enrichment endpoints while keeping existing analysis clients compatible.
func (h *Handler) WithDNS(service DNSService) *Handler {
	h.dns = service
	return h
}

func (h *Handler) enrichDNS(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 14*time.Second)
	defer cancel()
	domain := r.PathValue("domain")
	if id := r.PathValue("id"); id != "" {
		if !uuidPattern.MatchString(id) {
			writeError(w, 400, "invalid_id", "The analysis ID is invalid.")
			return
		}
		analysis, err := h.repo.Get(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeError(w, 404, "analysis_not_found", "No analysis exists with that ID.")
			} else {
				h.dnsError(w, err)
			}
			return
		}
		parsed, err := url.Parse(analysis.CandidateURL)
		if err != nil {
			h.dnsError(w, enrichment.ErrInvalidDomain)
			return
		}
		domain = parsed.Hostname()
	}
	result, err := h.dns.Enrich(ctx, domain)
	if err != nil {
		h.dnsError(w, err)
		return
	}
	// 200 for both cache hits and fresh observations: concurrent callers may
	// share creation of a single observation.
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) latestDNS(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	snapshot, err := h.dns.Latest(ctx, r.PathValue("domain"))
	if err != nil {
		h.dnsError(w, err)
		return
	}
	writeJSON(w, 200, snapshot)
}
func (h *Handler) dnsHistory(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			writeError(w, 400, "invalid_limit", "limit must be between 1 and 100.")
			return
		}
		limit = value
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	snapshots, err := h.dns.History(ctx, r.PathValue("domain"), limit)
	if err != nil {
		h.dnsError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"observations": snapshots})
}
func (h *Handler) dnsError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enrichment.ErrInvalidDomain):
		writeError(w, 422, "invalid_domain", enrichment.ErrInvalidDomain.Error())
	case errors.Is(err, enrichment.ErrNotFound):
		writeError(w, 404, "dns_not_found", "No DNS observation exists for this domain.")
	case errors.Is(err, enrichment.ErrBusy):
		w.Header().Set("Retry-After", "1")
		writeError(w, 503, "dns_busy", "DNS enrichment is busy. Try again shortly.")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeError(w, 504, "dns_deadline", "The DNS enrichment request deadline was reached.")
	default:
		h.logger.Error("DNS enrichment failed", "error", err)
		writeError(w, 500, "dns_storage_error", "The DNS observation could not be read or saved.")
	}
}
