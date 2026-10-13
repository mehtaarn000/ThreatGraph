package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPScorerPostsRequestAndDecodesScore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/score" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var body CreateAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if body.BrandName != "Acme" || body.CandidateURL != "https://acme-login.example" {
			t.Errorf("unexpected request body: %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ScoreResult{ImpersonationScore: 0.73, BrandName: body.BrandName, CandidateURL: body.CandidateURL, BrandDomain: body.BrandDomain})
	}))
	defer server.Close()

	scorer, err := NewHTTPScorer(server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scorer.Score(context.Background(), CreateAnalysisRequest{
		CandidateURL: "https://acme-login.example", BrandName: "Acme", BrandDomain: "acme.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ImpersonationScore != 0.73 || result.BrandName != "Acme" {
		t.Fatalf("unexpected score result: %+v", result)
	}
}

func TestHTTPScorerRejectsInvalidConfigurationAndUpstreamErrors(t *testing.T) {
	if _, err := NewHTTPScorer("file:///tmp/scorer", time.Second); err == nil {
		t.Fatal("expected non-HTTP scorer URL to fail")
	}
	if _, err := NewHTTPScorer("http://localhost:8000", 0); err == nil {
		t.Fatal("expected zero timeout to fail")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	scorer, err := NewHTTPScorer(server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scorer.Score(context.Background(), CreateAnalysisRequest{}); err == nil {
		t.Fatal("expected upstream error to be surfaced")
	}
}

func TestHTTPScorerRejectsMissingOrInvalidScores(t *testing.T) {
	for _, body := range []string{`{}`, `{"impersonation_score":null}`, `{"impersonation_score":2}`, `{"impersonation_score":0.5,"brand_name":"Wrong"}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			scorer, _ := NewHTTPScorer(server.URL, time.Second)
			if _, err := scorer.Score(context.Background(), CreateAnalysisRequest{}); err == nil {
				t.Fatal("expected invalid model response to fail")
			}
		})
	}
}

func TestHTTPScorerRejectsTrailingResponseData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"impersonation_score":0.5} {}`))
	}))
	defer server.Close()
	scorer, _ := NewHTTPScorer(server.URL, time.Second)
	if _, err := scorer.Score(context.Background(), CreateAnalysisRequest{}); err == nil {
		t.Fatal("expected trailing JSON to fail")
	}
}
