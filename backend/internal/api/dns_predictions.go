package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"time"

	"threatgraph/backend/internal/enrichment"
)

type DNSScore struct {
	SnapshotID         string    `json:"snapshot_id"`
	Domain             string    `json:"domain"`
	ObservedAt         time.Time `json:"observed_at"`
	Score              float64   `json:"generic_phishing_score"`
	Threshold          float64   `json:"threshold"`
	Flagged            bool      `json:"flagged"`
	Model              string    `json:"model"`
	ModelVersion       string    `json:"model_version"`
	ScoreSemantics     string    `json:"score_semantics"`
	Experimental       bool      `json:"experimental"`
	UnknownRecordTypes []string  `json:"unknown_record_types"`
}

type DNSPrediction struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	DNSScore
}

type DNSScorer interface {
	ScoreDNS(context.Context, enrichment.Snapshot) (DNSScore, error)
}

type DNSPredictionRepository interface {
	SaveDNSPrediction(context.Context, DNSScore) (DNSPrediction, error)
	DNSPredictions(context.Context, string) ([]DNSPrediction, error)
}

func (h *Handler) WithDNSScoring(scorer DNSScorer, repository DNSPredictionRepository) *Handler {
	h.dnsScorer, h.dnsPredictions = scorer, repository
	return h
}

var modelDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validateDNSScore(score DNSScore, snapshot enrichment.Snapshot) error {
	validNumber := func(value float64) bool {
		return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
	}
	if !validNumber(score.Score) || !validNumber(score.Threshold) || score.Flagged != (score.Score >= score.Threshold) {
		return fmt.Errorf("invalid DNS score or threshold")
	}
	if score.SnapshotID != snapshot.ID || score.Domain != snapshot.Domain || !score.ObservedAt.Equal(snapshot.ObservedAt) {
		return fmt.Errorf("DNS score does not match snapshot")
	}
	if !modelDigest.MatchString(score.ModelVersion) || score.Model == "" || score.ScoreSemantics == "" || !score.Experimental {
		return fmt.Errorf("missing DNS model provenance")
	}
	expected := map[string]bool{}
	for _, query := range snapshot.Queries {
		if query.Status != "ok" && query.Status != "no_records" && query.Status != "not_found" {
			expected[query.Type] = true
		}
	}
	if len(expected) != len(score.UnknownRecordTypes) {
		return fmt.Errorf("invalid unknown-record report")
	}
	for _, kind := range score.UnknownRecordTypes {
		if !expected[kind] {
			return fmt.Errorf("invalid unknown-record report")
		}
		delete(expected, kind)
	}
	return nil
}

func (s *HTTPScorer) ScoreDNS(ctx context.Context, snapshot enrichment.Snapshot) (DNSScore, error) {
	var payload struct {
		DNSScore
		Score     *float64 `json:"generic_phishing_score"`
		Threshold *float64 `json:"threshold"`
		Flagged   *bool    `json:"flagged"`
	}
	if err := s.do(ctx, http.MethodPost, "/v1/score/dns", snapshot, &payload); err != nil {
		return DNSScore{}, err
	}
	if payload.Score == nil || payload.Threshold == nil || payload.Flagged == nil {
		return DNSScore{}, fmt.Errorf("missing DNS score fields")
	}
	result := payload.DNSScore
	result.Score, result.Threshold, result.Flagged = *payload.Score, *payload.Threshold, *payload.Flagged
	return result, validateDNSScore(result, snapshot)
}

func (h *Handler) createDNSPrediction(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 24*time.Second)
	defer cancel()
	result, err := h.dns.Enrich(ctx, r.PathValue("domain"))
	if err != nil {
		h.dnsError(w, err)
		return
	}
	usable := false
	for _, query := range result.Snapshot.Queries {
		usable = usable || query.Status == "ok" || query.Status == "no_records" || query.Status == "not_found"
	}
	if !usable {
		writeError(w, 422, "insufficient_dns", "DNS lookups failed. Evidence was saved, but no prediction was made.")
		return
	}
	score, err := h.dnsScorer.ScoreDNS(ctx, result.Snapshot)
	if err == nil {
		err = validateDNSScore(score, result.Snapshot)
	}
	if err != nil {
		h.logger.Error("DNS scoring failed", "snapshot_id", result.Snapshot.ID, "error", err)
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = http.StatusGatewayTimeout
		}
		writeError(w, status, "dns_model_error", "DNS evidence was saved, but the model could not score it. Retry the request.")
		return
	}
	prediction, err := h.dnsPredictions.SaveDNSPrediction(ctx, score)
	if err != nil {
		h.logger.Error("save DNS prediction failed", "snapshot_id", result.Snapshot.ID, "error", err)
		writeError(w, 500, "prediction_storage_error", "The DNS prediction could not be saved.")
		return
	}
	// Repeated requests can reuse the same snapshot and artifact prediction.
	writeJSON(w, 200, prediction)
}

func (h *Handler) listDNSPredictions(w http.ResponseWriter, r *http.Request) {
	domain, err := enrichment.NormalizeDomain(r.PathValue("domain"))
	if err != nil {
		h.dnsError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	predictions, err := h.dnsPredictions.DNSPredictions(ctx, domain)
	if err != nil {
		h.logger.Error("read DNS predictions failed", "error", err)
		writeError(w, 500, "prediction_storage_error", "DNS predictions could not be read.")
		return
	}
	writeJSON(w, 200, map[string]any{"predictions": predictions})
}
