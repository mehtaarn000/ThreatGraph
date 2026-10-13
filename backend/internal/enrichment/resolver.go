package enrichment

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
	LookupNS(context.Context, string) ([]*net.NS, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
}

type Collector struct {
	resolver Resolver
	source   string
	timeout  time.Duration
}

func NewCollector(resolver Resolver, source string, timeout time.Duration) (*Collector, error) {
	if resolver == nil || source == "" || timeout <= 0 || timeout > 10*time.Second {
		return nil, fmt.Errorf("DNS collector requires a resolver, source, and timeout in (0, 10s]")
	}
	return &Collector{resolver: resolver, source: source, timeout: timeout}, nil
}

// NewResolver uses absolute questions and Go's resolver with optional server override.
// The configured server must be an IP:port so resolving it cannot recurse.
func NewResolver(server string) (*net.Resolver, string, error) {
	resolver := &net.Resolver{PreferGo: true}
	if server == "" {
		return resolver, "system", nil
	}
	host, port, err := net.SplitHostPort(server)
	number, portErr := strconv.Atoi(port)
	if err != nil || net.ParseIP(host) == nil || portErr != nil || number < 1 || number > 65535 {
		return nil, "", fmt.Errorf("DNS_SERVER must be an IP:port")
	}
	resolver.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server)
	}
	return resolver, server, nil
}

func (c *Collector) Collect(ctx context.Context, domain string) Snapshot {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	types := []string{"A", "AAAA", "NS", "MX"}
	results := make([]QueryResult, len(types))
	var wg sync.WaitGroup
	for i, kind := range types {
		wg.Add(1)
		go func(i int, kind string) {
			defer wg.Done()
			records, err := c.lookup(ctx, domain+".", kind)
			status := "ok"
			if err != nil {
				status = "error"
				var dnsErr *net.DNSError
				if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &dnsErr) && dnsErr.IsTimeout {
					status = "timeout"
				} else if errors.Is(err, context.Canceled) {
					status = "canceled"
				} else if dnsErr != nil && dnsErr.IsNotFound {
					status = "not_found"
				}
				records = []Record{}
			} else if len(records) == 0 {
				status = "no_records"
			}
			results[i] = QueryResult{Type: kind, Status: status, ObservedAt: time.Now().UTC(), Records: records}
		}(i, kind)
	}
	wg.Wait()
	return Snapshot{Domain: domain, Resolver: c.source, ObservedAt: time.Now().UTC(),
		Queries: results, Relationships: []Relationship{}}
}

func (c *Collector) lookup(ctx context.Context, domain, kind string) ([]Record, error) {
	records := []Record{}
	switch kind {
	case "A", "AAAA":
		network := "ip4"
		if kind == "AAAA" {
			network = "ip6"
		}
		ips, err := c.resolver.LookupIP(ctx, network, domain)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.To16() == nil {
				continue
			}
			if kind == "A" && ip.To4() == nil || kind == "AAAA" && ip.To4() != nil {
				continue
			}
			records = append(records, Record{Value: ip.String()})
		}
	case "NS":
		hosts, err := c.resolver.LookupNS(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, host := range hosts {
			if host != nil {
				records = append(records, Record{Value: strings.TrimSuffix(strings.ToLower(host.Host), ".")})
			}
		}
	case "MX":
		hosts, err := c.resolver.LookupMX(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, host := range hosts {
			if host == nil {
				continue
			}
			value := strings.TrimSuffix(strings.ToLower(host.Host), ".")
			if host.Host == "." {
				value = "."
			} // Null MX: this domain does not accept mail.
			pref := host.Pref
			records = append(records, Record{Value: value, Preference: &pref})
		}
	}
	seen := map[string]bool{}
	unique := []Record{}
	for _, record := range records {
		key := record.Value
		if record.Preference != nil {
			key += fmt.Sprintf("/%d", *record.Preference)
		}
		if record.Value != "" && !seen[key] {
			unique = append(unique, record)
			seen[key] = true
		}
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Preference != nil && unique[j].Preference != nil && *unique[i].Preference != *unique[j].Preference {
			return *unique[i].Preference < *unique[j].Preference
		}
		return unique[i].Value < unique[j].Value
	})
	return unique, nil
}
