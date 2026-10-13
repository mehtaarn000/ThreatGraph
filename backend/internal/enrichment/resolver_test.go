package enrichment

import (
	"context"
	"net"
	"testing"
	"time"
)

type fixtureResolver struct{}

func (fixtureResolver) LookupIP(ctx context.Context, network, domain string) ([]net.IP, error) {
	if domain != "example.test." {
		panic("question must be absolute")
	}
	if network == "ip6" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []net.IP{net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.1")}, nil
}
func (fixtureResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "NS1.EXAMPLE.TEST."}, {Host: "ns1.example.test."}}, nil
}
func (fixtureResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "MX.EXAMPLE.TEST.", Pref: 20}, {Host: "mail.example.test.", Pref: 10}}, nil
}
func TestCollectorRetainsSuccessfulRecordsWhenOneQueryTimesOut(t *testing.T) {
	c, err := NewCollector(fixtureResolver{}, "fixture", 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Collect(context.Background(), "example.test")
	if len(s.Queries) != 4 || s.Queries[1].Status != "timeout" {
		t.Fatalf("%+v", s)
	}
	if len(s.Queries[0].Records) != 2 || s.Queries[0].Records[0].Value != "192.0.2.1" {
		t.Fatal(s.Queries[0])
	}
	if len(s.Queries[2].Records) != 1 || s.Queries[2].Records[0].Value != "ns1.example.test" {
		t.Fatal(s.Queries[2])
	}
	if *s.Queries[3].Records[0].Preference != 10 {
		t.Fatal(s.Queries[3])
	}
	for _, q := range s.Queries {
		if q.ObservedAt.IsZero() {
			t.Fatal("missing timestamp")
		}
	}
}
func TestResolverConfiguration(t *testing.T) {
	for _, invalid := range []string{"localhost:53", "1.1.1.1", "1.1.1.1:0", "1.1.1.1:65536"} {
		if _, _, err := NewResolver(invalid); err == nil {
			t.Fatal(invalid)
		}
	}
	for _, valid := range []string{"", "127.0.0.1:5353", "[::1]:53"} {
		if _, _, err := NewResolver(valid); err != nil {
			t.Fatal(err)
		}
	}
}
