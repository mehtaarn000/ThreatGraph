// Package enrichment collects point-in-time DNS evidence for investigations.
package enrichment

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("DNS observation not found")
var ErrInvalidDomain = errors.New("provide a valid domain hostname, not a URL or IP address")

type Record struct {
	Value      string  `json:"value"`
	Preference *uint16 `json:"preference,omitempty"`
}
type QueryResult struct {
	Type       string    `json:"type"`
	Status     string    `json:"status"`
	ObservedAt time.Time `json:"observed_at"`
	Records    []Record  `json:"records"`
}
type Relationship struct {
	Source     string    `json:"source"`
	Target     string    `json:"target"`
	TargetType string    `json:"target_type"`
	Kind       string    `json:"kind"`
	RecordType string    `json:"record_type"`
	ObservedAt time.Time `json:"observed_at"`
	Preference *uint16   `json:"preference,omitempty"`
}
type Snapshot struct {
	ID            string         `json:"id"`
	Domain        string         `json:"domain"`
	Resolver      string         `json:"resolver"`
	ObservedAt    time.Time      `json:"observed_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Queries       []QueryResult  `json:"queries"`
	Relationships []Relationship `json:"relationships"`
}
type Result struct {
	Snapshot Snapshot `json:"snapshot"`
	Cached   bool     `json:"cached"`
}
type Repository interface {
	SaveDNS(context.Context, Snapshot) (Snapshot, error)
	LatestDNS(context.Context, string) (Snapshot, error)
	DNSHistory(context.Context, string, int) ([]Snapshot, error)
}
