package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeScorer struct {
	result ScoreResult
	err    error
	calls  int
}

func (f *fakeScorer) Score(_ context.Context, request CreateAnalysisRequest) (ScoreResult, error) {
	f.calls++
	if f.err != nil {
		return ScoreResult{}, f.err
	}
	result := f.result
	result.CandidateURL = request.CandidateURL
	result.BrandName = request.BrandName
	result.BrandDomain = request.BrandDomain
	return result, nil
}

func (f *fakeScorer) Ready(context.Context) error { return f.err }

type fakeRepository struct {
	analysis Analysis
	err      error
	created  bool
}

func (f *fakeRepository) Create(_ context.Context, request CreateAnalysisRequest, result ScoreResult) (Analysis, error) {
	f.created = true
	if f.err != nil {
		return Analysis{}, f.err
	}
	return Analysis{
		ID: "123e4567-e89b-12d3-a456-426614174000", CandidateURL: request.CandidateURL,
		BrandName: request.BrandName, BrandDomain: request.BrandDomain,
		Result: result, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}, nil
}

func (f *fakeRepository) Get(context.Context, string) (Analysis, error) {
	return f.analysis, f.err
}

func (f *fakeRepository) Ping(context.Context) error { return f.err }

func testHandler(scorer *fakeScorer, repo *fakeRepository) http.Handler {
	return NewHandler(scorer, repo, slog.New(slog.NewTextHandler(io.Discard, nil))).Routes()
}

func TestCreateAnalysisScoresAndPersists(t *testing.T) {
	scorer := &fakeScorer{result: ScoreResult{ImpersonationScore: 0.82, ScoreSemantics: "research only"}}
	repo := &fakeRepository{}
	handler := testHandler(scorer, repo)
	request := httptest.NewRequest(http.MethodPost, "/v1/analyses", strings.NewReader(`{"candidate_url":"https://acme-login.example/","brand_name":"Acme","brand_domain":"acme.example"}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !repo.created || scorer.calls != 1 {
		t.Fatalf("repo created=%v, scorer calls=%d", repo.created, scorer.calls)
	}
	if !strings.Contains(response.Body.String(), `"impersonation_score":0.82`) {
		t.Fatalf("response did not include score: %s", response.Body.String())
	}
}

func TestCreateAnalysisRejectsNonHTTPURLBeforeScoring(t *testing.T) {
	scorer := &fakeScorer{}
	repo := &fakeRepository{}
	handler := testHandler(scorer, repo)
	request := httptest.NewRequest(http.MethodPost, "/v1/analyses", strings.NewReader(`{"candidate_url":"file:///etc/passwd","brand_name":"Acme","brand_domain":"acme.example"}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if scorer.calls != 0 || repo.created {
		t.Fatalf("invalid request reached dependencies: scorer calls=%d, repo created=%v", scorer.calls, repo.created)
	}
}

func TestCreateAnalysisMapsScorerFailureToBadGateway(t *testing.T) {
	scorer := &fakeScorer{err: errors.New("connection refused")}
	repo := &fakeRepository{}
	handler := testHandler(scorer, repo)
	request := httptest.NewRequest(http.MethodPost, "/v1/analyses", strings.NewReader(`{"candidate_url":"https://acme-login.example/","brand_name":"Acme","brand_domain":"acme.example"}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if repo.created {
		t.Fatal("analysis persisted after scoring failed")
	}
}

func TestCreateAnalysisRejectsUnknownAndOversizedBodies(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field": `{"candidate_url":"https://acme.example","brand_name":"Acme","brand_domain":"acme.example","fetch":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			scorer := &fakeScorer{}
			repo := &fakeRepository{}
			request := httptest.NewRequest(http.MethodPost, "/v1/analyses", strings.NewReader(body))
			response := httptest.NewRecorder()
			testHandler(scorer, repo).ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if scorer.calls != 0 {
				t.Fatal("invalid request reached scorer")
			}
		})
	}

	scorer := &fakeScorer{}
	repo := &fakeRepository{}
	body := `{"candidate_url":"` + strings.Repeat("a", maxRequestBytes) + `","brand_name":"Acme","brand_domain":"acme.example"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/analyses", strings.NewReader(body))
	response := httptest.NewRecorder()
	testHandler(scorer, repo).ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGetAnalysisReturnsPersistedRecordAndMapsMissingID(t *testing.T) {
	analysis := Analysis{ID: "123e4567-e89b-12d3-a456-426614174000", BrandName: "Acme"}
	repo := &fakeRepository{analysis: analysis}
	handler := testHandler(&fakeScorer{}, repo)
	request := httptest.NewRequest(http.MethodGet, "/v1/analyses/"+analysis.ID, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"brand_name":"Acme"`) {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}

	repo.err = ErrNotFound
	request = httptest.NewRequest(http.MethodGet, "/v1/analyses/"+analysis.ID, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing record status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestReadinessRequiresBothDependencies(t *testing.T) {
	scorer := &fakeScorer{}
	repo := &fakeRepository{}
	handler := testHandler(scorer, repo)
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ready status = %d, body = %s", response.Code, response.Body.String())
	}

	repo.err = errors.New("database down")
	request = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unready status = %d, body = %s", response.Code, response.Body.String())
	}
}
