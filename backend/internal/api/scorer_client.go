package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	var result ScoreResult
	if err := s.do(ctx, http.MethodPost, "/v1/score", request, &result); err != nil {
		return ScoreResult{}, err
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
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode model response: %w", err)
	}
	return nil
}
