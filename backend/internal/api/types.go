package api

import "time"

type CreateAnalysisRequest struct {
	CandidateURL string `json:"candidate_url"`
	BrandName    string `json:"brand_name"`
	BrandDomain  string `json:"brand_domain"`
}

type FeatureContribution struct {
	Feature             string  `json:"feature"`
	Value               float64 `json:"value"`
	LogOddsContribution float64 `json:"log_odds_contribution"`
	Direction           string  `json:"direction"`
}

type ScoreResult struct {
	CandidateURL         string                `json:"candidate_url"`
	BrandName            string                `json:"brand_name"`
	BrandDomain          string                `json:"brand_domain"`
	ImpersonationScore   float64               `json:"impersonation_score"`
	ScoreSemantics       string                `json:"score_semantics"`
	FeatureContributions []FeatureContribution `json:"feature_contributions"`
	ExplanationSemantics string                `json:"explanation_semantics"`
}

type Analysis struct {
	ID           string      `json:"id"`
	CandidateURL string      `json:"candidate_url"`
	BrandName    string      `json:"brand_name"`
	BrandDomain  string      `json:"brand_domain"`
	Result       ScoreResult `json:"result"`
	CreatedAt    time.Time   `json:"created_at"`
}

type ErrorResponse struct {
	Error APIError `json:"error"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
