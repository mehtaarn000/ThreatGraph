package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"threatgraph/backend/internal/api"
)

//go:embed migrations/*.sql
var migrations embed.FS

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Postgres struct {
	db *sql.DB
}

func NewPostgres(db *sql.DB) *Postgres {
	return &Postgres{db: db}
}

func (p *Postgres) Migrate(ctx context.Context) error {
	files, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database migration: %w", err)
	}
	defer tx.Rollback()
	// Serialize startup migrations across API processes in this database.
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(746872656174)"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"); err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}
		var applied bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)", file.Name()).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		script, err := migrations.ReadFile("migrations/" + file.Name())
		if err != nil {
			return err
		}
		// Migrations currently contain plain SQL statements, no procedural blocks.
		for _, statement := range strings.Split(string(script), ";") {
			if strings.TrimSpace(statement) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply %s: %w", file.Name(), err)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (name) VALUES ($1)", file.Name()); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database migration: %w", err)
	}
	return nil
}

func (p *Postgres) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

func (p *Postgres) Create(ctx context.Context, request api.CreateAnalysisRequest, result api.ScoreResult) (api.Analysis, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return api.Analysis{}, fmt.Errorf("marshal analysis result: %w", err)
	}
	analysis := api.Analysis{CandidateURL: request.CandidateURL, BrandName: request.BrandName, BrandDomain: request.BrandDomain, Result: result}
	err = p.db.QueryRowContext(ctx, `
		INSERT INTO analyses (candidate_url, brand_name, brand_domain, impersonation_score, result)
		VALUES ($1, $2, $3, $4, $5::jsonb)
		RETURNING id::text, created_at`,
		request.CandidateURL, request.BrandName, request.BrandDomain, result.ImpersonationScore, string(resultJSON),
	).Scan(&analysis.ID, &analysis.CreatedAt)
	if err != nil {
		return api.Analysis{}, fmt.Errorf("insert analysis: %w", err)
	}
	return analysis, nil
}

func (p *Postgres) Get(ctx context.Context, id string) (api.Analysis, error) {
	if !uuidPattern.MatchString(id) {
		return api.Analysis{}, api.ErrNotFound
	}
	var analysis api.Analysis
	var resultJSON []byte
	err := p.db.QueryRowContext(ctx, `
		SELECT id::text, candidate_url, brand_name, brand_domain, result, created_at
		FROM analyses WHERE id = $1`, id,
	).Scan(&analysis.ID, &analysis.CandidateURL, &analysis.BrandName, &analysis.BrandDomain, &resultJSON, &analysis.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Analysis{}, api.ErrNotFound
	}
	if err != nil {
		return api.Analysis{}, fmt.Errorf("select analysis: %w", err)
	}
	if err := json.Unmarshal(resultJSON, &analysis.Result); err != nil {
		return api.Analysis{}, fmt.Errorf("decode stored analysis: %w", err)
	}
	return analysis, nil
}
