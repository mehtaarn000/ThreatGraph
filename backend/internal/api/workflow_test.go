package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// This repository exercises stateful API workflows without requiring Postgres.
// SQL behavior belongs in a separate database integration suite.
type workflowRepository struct {
	mu         sync.Mutex
	rows       map[string]Analysis
	failWrites bool
}

func (r *workflowRepository) Create(_ context.Context, req CreateAnalysisRequest, result ScoreResult) (Analysis, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failWrites {
		return Analysis{}, errors.New("private database detail")
	}
	id := fmt.Sprintf("00000000-0000-4000-8000-%012d", len(r.rows)+1)
	row := Analysis{ID: id, CandidateURL: req.CandidateURL, BrandName: req.BrandName,
		BrandDomain: req.BrandDomain, Result: result, CreatedAt: time.Now().UTC()}
	r.rows[id] = row
	return row, nil
}
func (r *workflowRepository) Get(_ context.Context, id string) (Analysis, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[id]
	if !ok {
		return Analysis{}, ErrNotFound
	}
	return row, nil
}
func (r *workflowRepository) Ping(context.Context) error { return nil }

func workflowRequest(t *testing.T, client *http.Client, method, url, body string, status int, target any) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != status {
		data, _ := io.ReadAll(res.Body)
		t.Fatalf("%s %s: status %d, want %d; %s", method, url, res.StatusCode, status, data)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store header")
	}
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func TestFunctionalCreateAndRetrieveAnalyses(t *testing.T) {
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/score" {
			http.Error(w, "unexpected model route", 404)
			return
		}
		var req CreateAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad JSON", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(ScoreResult{
			CandidateURL: req.CandidateURL, BrandName: req.BrandName, BrandDomain: req.BrandDomain,
			ImpersonationScore: .72, ScoreSemantics: "research only",
			ExplanationSemantics: "not proof",
			FeatureContributions: []FeatureContribution{{Feature: "brand_token_present", Value: 1, LogOddsContribution: .4, Direction: "raises score"}},
		})
	}))
	defer model.Close()
	scorer, err := NewHTTPScorer(model.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	repo := &workflowRepository{rows: make(map[string]Analysis)}
	server := httptest.NewServer(NewHandler(scorer, repo, slog.New(slog.NewTextHandler(io.Discard, nil))).Routes())
	defer server.Close()
	client := &http.Client{Timeout: 3 * time.Second}

	var ready map[string]string
	workflowRequest(t, client, "GET", server.URL+"/readyz", "", 200, &ready)
	if ready["status"] != "ready" {
		t.Fatalf("unexpected readiness: %v", ready)
	}
	ids := map[string]bool{}
	for _, brand := range []string{"Acme", "Northstar"} {
		body := fmt.Sprintf(`{"candidate_url":" https://candidate.example/login ","brand_name":" %s ","brand_domain":" brand.example "}`, brand)
		var created Analysis
		workflowRequest(t, client, "POST", server.URL+"/v1/analyses", body, 201, &created)
		if created.ID == "" || ids[created.ID] || created.CreatedAt.IsZero() {
			t.Fatal("invalid record identity")
		}
		ids[created.ID] = true
		if created.BrandName != brand || created.CandidateURL != "https://candidate.example/login" ||
			created.Result.BrandName != brand || created.Result.ImpersonationScore != .72 ||
			len(created.Result.FeatureContributions) != 1 {
			t.Fatalf("unexpected analysis: %+v", created)
		}
		var loaded Analysis
		workflowRequest(t, client, "GET", server.URL+"/v1/analyses/"+created.ID, "", 200, &loaded)
		if !reflect.DeepEqual(created, loaded) {
			t.Fatalf("stored analysis changed: %+v", loaded)
		}
	}
	var missing ErrorResponse
	workflowRequest(t, client, "GET", server.URL+"/v1/analyses/00000000-0000-4000-8000-999999999999", "", 404, &missing)
	if missing.Error.Code != "analysis_not_found" {
		t.Fatalf("unexpected error: %+v", missing)
	}
}

