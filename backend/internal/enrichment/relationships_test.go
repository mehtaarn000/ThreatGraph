package enrichment

import (
	"testing"
	"time"
)

func TestRelationshipsPreserveEvidenceAndExcludeNullMailAndFailures(t *testing.T) {
	now := time.Now().UTC()
	pref := uint16(0)
	s := Snapshot{Domain: "example.test", Queries: []QueryResult{
		{Type: "A", Status: "ok", ObservedAt: now, Records: []Record{{Value: "192.0.2.1"}}},
		{Type: "AAAA", Status: "timeout", Records: []Record{{Value: "2001:db8::1"}}},
		{Type: "NS", Status: "ok", ObservedAt: now, Records: []Record{{Value: "ns.example.test"}}},
		{Type: "MX", Status: "ok", ObservedAt: now, Records: []Record{{Value: ".", Preference: &pref}}},
	}}
	edges := RelationshipsFrom(s)
	if len(edges) != 2 || edges[0].Kind != "RESOLVES_TO" || edges[1].Kind != "USES_NAMESERVER" {
		t.Fatal(edges)
	}
	for _, edge := range edges {
		if edge.Source != s.Domain || !edge.ObservedAt.Equal(now) {
			t.Fatal(edge)
		}
	}
	s.Queries[3].Records[0].Value = "mail.example.test"
	edges = RelationshipsFrom(s)
	if len(edges) != 3 || edges[2].Kind != "MAIL_HANDLED_BY" || edges[2].Preference == nil || *edges[2].Preference != 0 {
		t.Fatal(edges)
	}
}
