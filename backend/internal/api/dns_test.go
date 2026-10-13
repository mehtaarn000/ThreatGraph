package api

import (
	"context"
	"net/http/httptest"
	"testing"
	"threatgraph/backend/internal/enrichment"
)

type fakeDNS struct {
	domain string
	err    error
}

func (f *fakeDNS) Enrich(_ context.Context, domain string) (enrichment.Result, error) {
	f.domain = domain
	return enrichment.Result{Snapshot: enrichment.Snapshot{Domain: domain}}, f.err
}
func (f *fakeDNS) Latest(context.Context, string) (enrichment.Snapshot, error) {
	return enrichment.Snapshot{}, f.err
}
func (f *fakeDNS) History(context.Context, string, int) ([]enrichment.Snapshot, error) {
	return []enrichment.Snapshot{}, f.err
}
func TestAnalysisDNSUsesCandidateHostname(t *testing.T) {
	dns := &fakeDNS{}
	h := NewHandler(&fakeScorer{}, &fakeRepository{analysis: Analysis{CandidateURL: "https://candidate.test/login"}}, nil).WithDNS(dns).Routes()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/analyses/123e4567-e89b-12d3-a456-426614174000/dns", nil))
	if w.Code != 200 || dns.domain != "candidate.test" {
		t.Fatalf("%d %s", w.Code, dns.domain)
	}
}
func TestDNSRouteErrors(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		err          error
		status       int
	}{
		{"POST", "/v1/domains/example.test/dns", enrichment.ErrInvalidDomain, 422},
		{"GET", "/v1/domains/example.test/dns", enrichment.ErrNotFound, 404},
		{"POST", "/v1/domains/example.test/dns", enrichment.ErrBusy, 503},
		{"GET", "/v1/domains/example.test/dns/history?limit=101", nil, 400},
		{"GET", "/v1/domains/example.test/dns/history?limit=bad", nil, 400},
	} {
		h := NewHandler(&fakeScorer{}, &fakeRepository{}, nil).WithDNS(&fakeDNS{err: tc.err}).Routes()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}
