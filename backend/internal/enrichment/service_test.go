package enrichment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryDNS struct {
	mu      sync.Mutex
	rows    []Snapshot
	saveErr error
}

func (m *memoryDNS) SaveDNS(_ context.Context, s Snapshot) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return Snapshot{}, m.saveErr
	}
	s.ID = fmt.Sprint(len(m.rows) + 1)
	m.rows = append(m.rows, s)
	return s, nil
}
func (m *memoryDNS) LatestDNS(context.Context, string) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rows) == 0 {
		return Snapshot{}, ErrNotFound
	}
	return m.rows[len(m.rows)-1], nil
}
func (m *memoryDNS) DNSHistory(context.Context, string, int) ([]Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Snapshot{}, m.rows...), nil
}

type countingResolver struct {
	calls   atomic.Int32
	ipError error
}

func (r *countingResolver) LookupIP(_ context.Context, network, _ string) ([]net.IP, error) {
	r.calls.Add(1)
	if r.ipError != nil {
		return nil, r.ipError
	}
	if network == "ip4" {
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	}
	return []net.IP{net.ParseIP("2001:db8::1")}, nil
}
func (r *countingResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	r.calls.Add(1)
	return []*net.NS{{Host: "ns.test."}}, nil
}
func (r *countingResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	r.calls.Add(1)
	return []*net.MX{{Host: "mx.test.", Pref: 10}}, nil
}
func serviceFixture(t *testing.T, resolver *countingResolver, repo *memoryDNS) *Service {
	t.Helper()
	c, err := NewCollector(resolver, "test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewService(c, repo, time.Minute, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestCacheReuseExpiryAndResolverProvenance(t *testing.T) {
	r, repo := &countingResolver{}, &memoryDNS{}
	s := serviceFixture(t, r, repo)
	first, err := s.Enrich(context.Background(), "EXAMPLE.TEST.")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Enrich(context.Background(), "example.test")
	if err != nil || !second.Cached || second.Snapshot.ID != first.Snapshot.ID || r.calls.Load() != 4 {
		t.Fatalf("%+v %v", second, err)
	}
	if !first.Snapshot.ExpiresAt.Equal(first.Snapshot.ObservedAt.Add(time.Minute)) {
		t.Fatal(first)
	}
	s.now = func() time.Time { return first.Snapshot.ExpiresAt }
	third, err := s.Enrich(context.Background(), "example.test")
	if err != nil || third.Cached || third.Snapshot.ID == first.Snapshot.ID || r.calls.Load() != 8 {
		t.Fatalf("%+v %v", third, err)
	}
	other := serviceFixture(t, r, repo)
	other.collector.source = "different-resolver"
	result, err := other.Enrich(context.Background(), "example.test")
	if err != nil || result.Cached || r.calls.Load() != 12 {
		t.Fatalf("%+v %v", result, err)
	}
}
func TestNegativeAnswersHaveShortCacheButTransientFailuresAreRetried(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		cached bool
		ttl    time.Duration
	}{
		{"negative", &net.DNSError{IsNotFound: true}, true, 2 * time.Second},
		{"timeout", context.DeadlineExceeded, false, 0},
		{"server error", errors.New("server failed"), false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingResolver{ipError: tc.err}
			s := serviceFixture(t, r, &memoryDNS{})
			first, err := s.Enrich(context.Background(), "example.test")
			if err != nil {
				t.Fatal(err)
			}
			if !first.Snapshot.ExpiresAt.Equal(first.Snapshot.ObservedAt.Add(tc.ttl)) {
				t.Fatal(first)
			}
			second, err := s.Enrich(context.Background(), "example.test")
			if err != nil || second.Cached != tc.cached {
				t.Fatalf("%+v %v", second, err)
			}
			want := int32(8)
			if tc.cached {
				want = 4
			}
			if r.calls.Load() != want {
				t.Fatal(r.calls.Load())
			}
		})
	}
}
func TestConcurrentRequestsShareOneObservation(t *testing.T) {
	r, repo := &countingResolver{}, &memoryDNS{}
	s := serviceFixture(t, r, repo)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.Enrich(context.Background(), "example.test")
			if err != nil || result.Snapshot.ID != "1" {
				t.Errorf("%+v %v", result, err)
			}
		}()
	}
	wg.Wait()
	if r.calls.Load() != 4 {
		t.Fatal(r.calls.Load())
	}
}
func TestCanceledCallerAndPersistenceFailure(t *testing.T) {
	r := &countingResolver{}
	s := serviceFixture(t, r, &memoryDNS{saveErr: errors.New("database unavailable")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Enrich(ctx, "example.test"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if r.calls.Load() != 0 {
		t.Fatal("canceled call queried DNS")
	}
	if _, err := s.Enrich(context.Background(), "example.test"); err == nil {
		t.Fatal("save failure ignored")
	}
}
