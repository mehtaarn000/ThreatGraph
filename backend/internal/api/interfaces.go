package api

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("analysis not found")

type Scorer interface {
	Score(context.Context, CreateAnalysisRequest) (ScoreResult, error)
	Ready(context.Context) error
}

type Repository interface {
	Create(context.Context, CreateAnalysisRequest, ScoreResult) (Analysis, error)
	Get(context.Context, string) (Analysis, error)
	Ping(context.Context) error
}
