package enrichment

// RelationshipsFrom projects observed evidence, not campaign membership.
// A null MX remains in the observation but is not a mail-server relationship.
func RelationshipsFrom(snapshot Snapshot) []Relationship {
	edges := []Relationship{}
	for _, query := range snapshot.Queries {
		if query.Status != "ok" {
			continue
		}
		kind, targetType := "", "domain"
		switch query.Type {
		case "A", "AAAA":
			kind, targetType = "RESOLVES_TO", "ip"
		case "NS":
			kind = "USES_NAMESERVER"
		case "MX":
			kind = "MAIL_HANDLED_BY"
		default:
			continue
		}
		for _, record := range query.Records {
			if record.Value == "" || record.Value == "." {
				continue
			}
			edges = append(edges, Relationship{
				Source: snapshot.Domain, Target: record.Value, TargetType: targetType,
				Kind: kind, RecordType: query.Type, ObservedAt: query.ObservedAt, Preference: record.Preference,
			})
		}
	}
	return edges
}
