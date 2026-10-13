package enrichment

import (
	"fmt"
	"time"
)

func ConfiguredService(repo Repository, getenv func(string) string) (*Service, error) {
	durations := map[string]time.Duration{
		"DNS_LOOKUP_TIMEOUT":     2 * time.Second,
		"DNS_CACHE_TTL":          5 * time.Minute,
		"DNS_NEGATIVE_CACHE_TTL": 30 * time.Second,
	}
	for name := range durations {
		if raw := getenv(name); raw != "" {
			value, err := time.ParseDuration(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			durations[name] = value
		}
	}
	resolver, source, err := NewResolver(getenv("DNS_SERVER"))
	if err != nil {
		return nil, err
	}
	collector, err := NewCollector(resolver, source, durations["DNS_LOOKUP_TIMEOUT"])
	if err != nil {
		return nil, err
	}
	return NewService(collector, repo, durations["DNS_CACHE_TTL"], durations["DNS_NEGATIVE_CACHE_TTL"])
}
