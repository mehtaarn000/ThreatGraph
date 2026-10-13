package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"threatgraph/backend/internal/enrichment"
)

func predictionFixture() (enrichment.Snapshot, DNSScore) {
	snapshot := enrichment.Snapshot{ID: "123e4567-e89b-12d3-a456-426614174000", Domain: "example.test", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 123456789, time.UTC)}
	score := DNSScore{SnapshotID: snapshot.ID, Domain: snapshot.Domain, ObservedAt: snapshot.ObservedAt,
		Score: .8, Threshold: .5, Flagged: true, Model: "fixture", ModelVersion: strings.Repeat("a", 64),
		ScoreSemantics: "experimental", Experimental: true, UnknownRecordTypes: []string{}}
	return snapshot, score
}

func TestDNSScorerValidatesContract(t *testing.T) {
	for _, mutation := range []string{"valid", "missing_score", "missing_threshold", "missing_flag", "wrong_snapshot", "wrong_time", "bad_version", "wrong_flag", "unknown_record"} {
		t.Run(mutation, func(t *testing.T) {
			snapshot, score := predictionFixture()
			encoded, _ := json.Marshal(score)
			var payload map[string]any
			_ = json.Unmarshal(encoded, &payload)
			switch mutation {
			case "missing_score":
				delete(payload, "generic_phishing_score")
			case "missing_threshold":
				delete(payload, "threshold")
			case "missing_flag":
				delete(payload, "flagged")
			case "wrong_snapshot":
				payload["snapshot_id"] = "another"
			case "wrong_time":
				payload["observed_at"] = "2026-01-01T00:00:00Z"
			case "bad_version":
				payload["model_version"] = "unknown"
			case "wrong_flag":
				payload["flagged"] = false
			case "unknown_record":
				payload["unknown_record_types"] = []string{"MX"}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/score/dns" || r.Method != "POST" {
					t.Error("wrong endpoint")
				}
				_ = json.NewEncoder(w).Encode(payload)
			}))
			defer server.Close()
			client, _ := NewHTTPScorer(server.URL, time.Second)
			result, err := client.ScoreDNS(context.Background(), snapshot)
			if mutation == "valid" {
				if err != nil || result.Score != .8 {
					t.Fatalf("%v %v", result, err)
				}
			} else if err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}

func TestDNSScorerHonorsDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}))
	defer server.Close()
	client, _ := NewHTTPScorer(server.URL, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	snapshot, _ := predictionFixture()
	_, err := client.ScoreDNS(ctx, snapshot)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
}
