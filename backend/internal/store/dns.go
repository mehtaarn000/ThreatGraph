package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"threatgraph/backend/internal/enrichment"
)

func (p *Postgres) SaveDNS(ctx context.Context, snapshot enrichment.Snapshot) (enrichment.Snapshot, error) {
	snapshot.ID = ""
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return enrichment.Snapshot{}, err
	}
	err = p.db.QueryRowContext(ctx, `
		INSERT INTO dns_observations (domain, observed_at, expires_at, payload)
		VALUES ($1, $2, $3, $4::jsonb) RETURNING id::text`,
		snapshot.Domain, snapshot.ObservedAt, snapshot.ExpiresAt, string(payload),
	).Scan(&snapshot.ID)
	if err != nil {
		return enrichment.Snapshot{}, fmt.Errorf("save DNS observation: %w", err)
	}
	return snapshot, nil
}

func (p *Postgres) LatestDNS(ctx context.Context, domain string) (enrichment.Snapshot, error) {
	observations, err := p.DNSHistory(ctx, domain, 1)
	if err != nil {
		return enrichment.Snapshot{}, err
	}
	if len(observations) == 0 {
		return enrichment.Snapshot{}, enrichment.ErrNotFound
	}
	return observations[0], nil
}

func (p *Postgres) DNSHistory(ctx context.Context, domain string, limit int) ([]enrichment.Snapshot, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("DNS history limit must be 1..100")
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT id::text, payload FROM dns_observations WHERE domain = $1
		ORDER BY observed_at DESC, id DESC LIMIT $2`, domain, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	snapshots := []enrichment.Snapshot{}
	for rows.Next() {
		var id string
		var payload []byte
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, err
		}
		var snapshot enrichment.Snapshot
		if err := json.Unmarshal(payload, &snapshot); err != nil {
			return nil, err
		}
		snapshot.ID = id
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, rows.Err()
}

// Keep the compile-time contract next to the implementation.
var _ enrichment.Repository = (*Postgres)(nil)
