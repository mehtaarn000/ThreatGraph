package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPScorer struct {
	baseURL string
	client  *http.Client
}

func NewHTTPScorer(baseURL string, timeout time.Duration) (*HTTPScorer, error) {
	parsed, err := url.ParseRequestURI(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("scorer URL must be an absolute HTTP(S) URL")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("scorer timeout must be positive")
	}
	return &HTTPScorer{baseURL: strings.TrimRight(baseURL, "/"), client: &http.Client{Timeout: timeout}}, nil
}

func (s *HTTPScorer) Score(ctx context.Context, request CreateAnalysisRequest) (ScoreResult, error) {
	var payload struct {
		ScoreResult
		Score *float64 `json:"impersonation_score"`
	}
	if err := s.do(ctx, http.MethodPost, "/v1/score", request, &payload); err != nil {
		return ScoreResult{}, err
	}
	if payload.Score == nil || math.IsNaN(*payload.Score) || math.IsInf(*payload.Score, 0) || *payload.Score < 0 || *payload.Score > 1 {
		return ScoreResult{}, fmt.Errorf("model response has an invalid or missing score")
	}
	result := payload.ScoreResult
	result.ImpersonationScore = *payload.Score
	if result.CandidateURL != request.CandidateURL || result.BrandName != request.BrandName || result.BrandDomain != request.BrandDomain {
		return ScoreResult{}, fmt.Errorf("model response does not match the requested pair")
	}
	return result, nil
}

func (s *HTTPScorer) Ready(ctx context.Context) error {
	var response map[string]string
	return s.do(ctx, http.MethodGet, "/healthz", nil, &response)
}

func (s *HTTPScorer) do(ctx context.Context, method, path string, body, output any) error {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode scorer request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, requestBody)
	if err != nil {
		return fmt.Errorf("create scorer request: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("call model service: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("model service returned HTTP %d", response.StatusCode)
	}
	const maxResponseBytes = 1 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read model response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("model response exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode model response: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("model response must contain exactly one JSON value")
	}
	return nil
}
