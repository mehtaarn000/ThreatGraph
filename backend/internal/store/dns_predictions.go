package store

import (
	"context"
	"encoding/json"

	"threatgraph/backend/internal/api"
)

func (p *Postgres) SaveDNSPrediction(ctx context.Context, score api.DNSScore) (api.DNSPrediction, error) {
	payload, err := json.Marshal(score)
	if err != nil {
		return api.DNSPrediction{}, err
	}
	var prediction api.DNSPrediction
	var saved []byte
	// Preserve the first result for this immutable snapshot/artifact pair.
	err = p.db.QueryRowContext(ctx, `
        INSERT INTO dns_predictions (snapshot_id, model_version, result)
        VALUES ($1, $2, $3::jsonb)
        ON CONFLICT (snapshot_id, model_version) DO UPDATE SET model_version = EXCLUDED.model_version
        RETURNING id::text, created_at, result`, score.SnapshotID, score.ModelVersion, string(payload),
	).Scan(&prediction.ID, &prediction.CreatedAt, &saved)
	if err != nil {
		return api.DNSPrediction{}, err
	}
	err = json.Unmarshal(saved, &prediction.DNSScore)
	return prediction, err
}

func (p *Postgres) DNSPredictions(ctx context.Context, domain string) ([]api.DNSPrediction, error) {
	rows, err := p.db.QueryContext(ctx, `
        SELECT p.id::text, p.created_at, p.result
        FROM dns_predictions p JOIN dns_observations d ON d.id = p.snapshot_id
        WHERE d.domain = $1 ORDER BY p.created_at DESC, p.id DESC LIMIT 100`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	predictions := []api.DNSPrediction{}
	for rows.Next() {
		var prediction api.DNSPrediction
		var payload []byte
		if err := rows.Scan(&prediction.ID, &prediction.CreatedAt, &payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &prediction.DNSScore); err != nil {
			return nil, err
		}
		predictions = append(predictions, prediction)
	}
	return predictions, rows.Err()
}

var _ api.DNSPredictionRepository = (*Postgres)(nil)
