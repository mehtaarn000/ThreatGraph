package enrichment

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/singleflight"
)

var ErrBusy = errors.New("DNS enrichment capacity reached")

type Service struct {
	collector   *Collector
	repo        Repository
	cacheTTL    time.Duration
	negativeTTL time.Duration
	flights     singleflight.Group
	slots       chan struct{}
	now         func() time.Time
}

func NewService(collector *Collector, repo Repository, cacheTTL, negativeTTL time.Duration) (*Service, error) {
	if collector == nil || repo == nil || cacheTTL <= 0 || negativeTTL <= 0 || cacheTTL > 24*time.Hour || negativeTTL > cacheTTL {
		return nil, fmt.Errorf("DNS cache lifetimes must satisfy 0 < negative TTL <= cache TTL <= 24h")
	}
	return &Service{collector: collector, repo: repo, cacheTTL: cacheTTL, negativeTTL: negativeTTL,
		slots: make(chan struct{}, 16), now: time.Now}, nil
}

func (s *Service) Enrich(ctx context.Context, domain string) (Result, error) {
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	// A leader's disconnected request must not cancel another caller's lookup.
	// Work is bounded by the lookup deadline plus two 2-second DB operations.
	ch := s.flights.DoChan(domain, func() (any, error) {
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		default:
			return Result{}, ErrBusy
		}
		dbCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		previous, err := s.repo.LatestDNS(dbCtx, domain)
		cancel()
		if err != nil && !errors.Is(err, ErrNotFound) {
			return Result{}, err
		}
		if err == nil && previous.Resolver == s.collector.source && s.now().Before(previous.ExpiresAt) {
			return Result{Snapshot: previous, Cached: true}, nil
		}
		snapshot := s.collector.Collect(context.Background(), domain)
		snapshot.Relationships = RelationshipsFrom(snapshot)
		lifetime := s.cacheTTL
		for _, query := range snapshot.Queries {
			switch query.Status {
			case "ok":
			case "no_records", "not_found":
				if s.negativeTTL < lifetime {
					lifetime = s.negativeTTL
				}
			default:
				lifetime = 0 // Preserve failures as history but retry on the next request.
			}
		}
		snapshot.ExpiresAt = snapshot.ObservedAt.Add(lifetime)
		dbCtx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		snapshot, err = s.repo.SaveDNS(dbCtx, snapshot)
		return Result{Snapshot: snapshot}, err
	})
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case result := <-ch:
		if result.Err != nil {
			return Result{}, result.Err
		}
		return result.Val.(Result), nil
	}
}

func (s *Service) Latest(ctx context.Context, domain string) (Snapshot, error) {
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return Snapshot{}, err
	}
	return s.repo.LatestDNS(ctx, domain)
}
func (s *Service) History(ctx context.Context, domain string, limit int) ([]Snapshot, error) {
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("limit must be 1..100")
	}
	return s.repo.DNSHistory(ctx, domain, limit)
}
