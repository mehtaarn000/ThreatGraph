package enrichment

import "testing"

func TestInvalidDNSConfigurationFailsAtStartup(t *testing.T) {
	for name, value := range map[string]string{
		"DNS_LOOKUP_TIMEOUT": "0s", "DNS_CACHE_TTL": "25h", "DNS_NEGATIVE_CACHE_TTL": "6m", "DNS_SERVER": "localhost:53",
	} {
		_, err := ConfiguredService(&memoryDNS{}, func(key string) string {
			if key == name {
				return value
			}
			return ""
		})
		if err == nil {
			t.Fatalf("accepted %s=%s", name, value)
		}
	}
	if _, err := ConfiguredService(&memoryDNS{}, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
}
